// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

type providerRefreshE2EOptions struct {
	access, idle, absolute int
	unselected, persistent bool
	excludeLocal           bool
	transforms             []string
	edit                   func(*authn.PortalConfig)
	wrapProvider           func(idp.IdentityProvider) idp.IdentityProvider
	wantConfigError        string
}

type providerRefreshE2E struct {
	server     *httptest.Server
	client     *http.Client
	issuer     *oidcE2EIssuer
	restart    func()
	closeState func() error
}

func newProviderRefreshE2E(t *testing.T, options providerRefreshE2EOptions) *providerRefreshE2E {
	t.Helper()
	issuer := newOIDCE2EIssuer(t, "Ed25519", "userinfo", "", false)
	issuer.issueRefreshToken = true
	issuer.identityClaims = map[string]any{"sid": "upstream-sid", "auth_time": int64(1), "amr": []string{"mfa"}, "acr": "upstream-high"}
	issuer.userInfoClaims = map[string]any{"tenant": "one", "nested": map[string]any{"access_token": "nested-provider-secret", "label": "retained"}}
	var runtimeMu sync.RWMutex
	var portal *authn.Portal
	var gatekeeper *authz.Gatekeeper
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtimeMu.RLock()
		defer runtimeMu.RUnlock()
		if r.URL.Path == "/protected" {
			ar := requests.NewAuthorizationRequest()
			_ = gatekeeper.Authenticate(w, r, ar)
			if ar.Response.Authorized {
				w.Write([]byte("protected-resource"))
			}
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("portal execution failed")
		}
	}))
	t.Cleanup(server.Close)
	providerConfig, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", []string{
		"driver generic", "realm upstream", "client_id " + oidcE2EClientID, "client_secret " + oidcE2EClientSecret,
		"base_auth_url " + issuer.server.URL, "metadata_url " + issuer.server.URL + "/.well-known/openid-configuration",
		"tls verification disabled", "user_info_fields all",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := idp.NewIdentityProvider(providerConfig, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.(*oauth.IdentityProvider).Close)
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}
	if options.wrapProvider != nil {
		provider = options.wrapProvider(provider)
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{"path": newJWKSE2EDatabase(t), "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	access, idle, absolute := options.access, options.idle, options.absolute
	if access == 0 {
		access = 60
	}
	if idle == 0 {
		idle = 120
	}
	if absolute == 0 {
		absolute = 240
	}
	lines := []string{"realms local upstream", "provider revalidation upstream snapshot", "public origin " + server.URL, "base path /auth", fmt.Sprintf("access lifetime %d", access), fmt.Sprintf("idle timeout %d", idle), fmt.Sprintf("absolute timeout %d", absolute), "max sessions 1"}
	if options.excludeLocal {
		lines[0] = "realms upstream"
	}
	if options.unselected {
		lines[0] = "realms local"
		lines = append(lines[:1], lines[2:]...)
	}
	refresh, err := refreshparser.NewTokenRefreshConfigFromDirectives(lines)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"crypto default token name oauth_portal_token", "crypto default token lifetime 600", "crypto key portal-hmac sign-verify " + oidcE2EPortalSecret}
	cookies := cookie.NewConfig()
	cookies.AccessTokenCookieName = "oauth_portal_token"
	cfg := &authn.PortalConfig{Name: "provider-refresh", IdentityStores: []string{"local"}, IdentityProviders: []string{"upstream"}, CookieConfig: cookies, RawCryptoKeyStoreConfig: keys, RefreshTokens: refresh,
		AccessListConfigs: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer userinfo-user mapped"}, Action: "allow stop"}}}
	setPolicy := func(lines []string) {
		cfg.UserTransformerConfigs = nil
		if len(lines) > 0 {
			c, err := transformparser.NewUserTransformerConfigFromDirectives(lines)
			if err != nil {
				t.Fatal(err)
			}
			cfg.UserTransformerConfigs = append(cfg.UserTransformerConfigs, c)
		}
	}
	setPolicy(options.transforms)
	if options.edit != nil {
		options.edit(cfg)
	}
	// Consumer configuration survives persisted JSON and revalidation.
	var restored authn.PortalConfig
	if err := json.Unmarshal(oidcE2EJSON(t, cfg), &restored); err != nil {
		t.Fatal(err)
	}
	cfg = &restored
	params := authn.PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}, IdentityProviders: []idp.IdentityProvider{provider}}
	var storage *state.Store
	stateDir := filepath.Join(t.TempDir(), "state")
	construct := func() error {
		var err error
		portal, err = authn.NewPortal(params)
		if err != nil {
			return err
		}
		if options.persistent {
			storage, err = state.Open(&state.Config{Directory: stateDir})
			if err != nil {
				return err
			}
			binding, err := state.Binding(map[string]any{"portal": cfg, "provider": providerConfig})
			if err != nil {
				return err
			}
			return portal.ConfigurePersistentState(storage, binding)
		}
		return nil
	}
	if err := construct(); err != nil {
		if options.wantConfigError != "" && strings.Contains(err.Error(), options.wantConfigError) {
			return nil
		}
		t.Fatal("construct provider refresh portal", err)
	}
	t.Cleanup(func() {
		portal.Close()
		if storage != nil {
			if err := storage.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	if options.wantConfigError != "" {
		t.Fatal("invalid provider configuration accepted")
	}
	gatekeeper, err = authz.NewGatekeeper(&authz.PolicyConfig{Name: "provider-refresh", AuthURLPath: "/auth/login", ValidateBearerHeader: true, AccessTokenCookieNames: []string{"oauth_portal_token"}, RawCryptoKeyStoreConfig: keys, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer userinfo-user mapped"}, Action: "allow stop"}}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gatekeeper.Close)
	issuer.callback = server.URL + "/auth/oauth2/upstream/authorization-code-callback"
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	pool.AddCert(issuer.server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := &providerRefreshE2E{server: server, client: client, issuer: issuer}
	if storage != nil {
		f.closeState = func() error { return storage.Close() }
	}
	f.restart = func() {
		runtimeMu.Lock()
		defer runtimeMu.Unlock()
		portal.Close()
		if storage != nil {
			if err := storage.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if err := construct(); err != nil {
			t.Fatal(err)
		}
	}
	// Last cleanup drains requests before disposing their runtimes.
	t.Cleanup(server.Close)
	return f
}

func (f *providerRefreshE2E) send(t *testing.T, method, path, body string, cookies []*http.Cookie) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if path == "/auth/login" {
		req.Header.Set("Accept", "application/json")
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", f.server.URL)
		req.Header.Set("X-Authcrunch-Refresh", "1")
		req.Header.Set("Content-Type", "application/json")
	}
	client := *f.client
	if cookies != nil {
		client.Jar = nil
		for _, c := range cookies {
			req.AddCookie(c)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("portal request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	f.assertNoProviderCredentials(t, resp.Header, data)
	return resp.StatusCode, resp.Header, data
}

func (f *providerRefreshE2E) assertNoProviderCredentials(t *testing.T, headers http.Header, data []byte) {
	t.Helper()
	f.issuer.mu.Lock()
	identity := f.issuer.lastIdentity
	subject := f.issuer.lastSubject
	f.issuer.mu.Unlock()
	for _, secret := range []string{"synthetic-upstream-refresh-secret", "nested-provider-secret", identity, "opaque-" + subject, oidcE2EClientSecret} {
		if secret == "" || secret == "opaque-" {
			continue
		}
		if strings.Contains(fmt.Sprint(headers), secret) || strings.Contains(string(data), secret) {
			t.Fatal("portal response exposed an upstream credential")
		}
	}
}

func (f *providerRefreshE2E) login(t *testing.T, want int, callbackHeaders ...http.Header) (string, http.Header) {
	t.Helper()
	location := f.server.URL + "/auth/oauth2/upstream"
	for step := range 3 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
		if err != nil {
			t.Fatal(err)
		}
		if step == 2 {
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Dest", "document")
			if len(callbackHeaders) != 0 {
				maps.Copy(req.Header, callbackHeaders[0])
			}
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal("OAuth request failed")
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if step < 2 {
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("OAuth step %d returned %d", step, resp.StatusCode)
			}
			location = resp.Header.Get("Location")
			continue
		}
		f.assertNoProviderCredentials(t, resp.Header, data)
		if resp.StatusCode != want {
			t.Fatalf("callback returned %d, want %d", resp.StatusCode, want)
		}
		return location, resp.Header
	}
	return "", nil
}

func TestE2ETokenRefreshProviderCallbackOrigin(t *testing.T) {
	for name, headers := range map[string]http.Header{
		"foreign origin":    {"Origin": {"https://foreign.example.test"}},
		"duplicate origin":  {"Origin": {"https://foreign.example.test", "https://foreign.example.test"}},
		"fetch mode":        {"Sec-Fetch-Mode": {"cors"}},
		"fetch destination": {"Sec-Fetch-Dest": {"empty"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{})
			callback, result := f.login(t, http.StatusForbidden, headers)
			for _, cookie := range (&http.Response{Header: result}).Cookies() {
				if cookie.Value != "" && cookie.MaxAge >= 0 {
					t.Fatal("rejected navigation delivered credentials")
				}
			}
			resp, err := f.client.Get(callback)
			if err != nil {
				t.Fatal("callback replay failed")
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatal("rejected callback state was not consumed")
			}
			// The rejected callback must leave capacity for independent fresh login.
			f.login(t, http.StatusSeeOther)
		})
	}
}

func providerRefreshCookie(t *testing.T, headers http.Header, name string) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: headers}).Cookies() {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	t.Fatal("missing credential cookie", name)
	return nil
}

func providerRefreshClaims(t *testing.T, cookie *http.Cookie) jwtlib.MapClaims {
	t.Helper()
	parsed, err := jwtlib.Parse(cookie.Value, func(token *jwtlib.Token) (any, error) {
		if token.Method != jwtlib.SigningMethodHS512 {
			t.Fatal("unexpected portal algorithm")
		}
		return []byte(oidcE2EPortalSecret), nil
	}, jwtlib.WithValidMethods([]string{"HS512"}), jwtlib.WithoutClaimsValidation())
	if err != nil || !parsed.Valid {
		t.Fatal("portal signature verification failed")
	}
	return parsed.Claims.(jwtlib.MapClaims)
}

func TestE2ETokenRefreshProviderLifecycle(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{access: 2, idle: 60, absolute: 120, persistent: true, transforms: []string{"match realm upstream", "action add role mapped", "overwrite sub attempted-rewrite", "add provider_name {claims.name} as string"}})
	callback, headers := f.login(t, http.StatusSeeOther)
	first := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
	access := providerRefreshCookie(t, headers, "oauth_portal_token")
	claims := providerRefreshClaims(t, access)
	if headers.Get("Authorization") != "" || first.Domain != "" || first.Path != "/auth" || !first.Secure || !first.HttpOnly || first.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe provider refresh delivery")
	}
	if claims["sub"] != f.issuer.lastSubject || claims["auth_time"].(float64) <= 1 || fmt.Sprint(claims["amr"]) != "[federated]" || claims["acr"] != nil || !strings.Contains(fmt.Sprint(claims["roles"]), "mapped") {
		t.Fatal("provider replaced proof or transform missing")
	}
	// The callback is single-use even with the correct browser binding.
	url, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := f.send(t, http.MethodGet, url.RequestURI(), "", nil); status != http.StatusUnauthorized {
		t.Fatal("callback replay admitted", status)
	}
	// A real access JWT expires; the public refresh endpoint still renews.
	deadline := time.Unix(int64(claims["exp"].(float64)), 0)
	if delay := time.Until(deadline); delay > 0 {
		time.Sleep(delay + 20*time.Millisecond)
	}
	if status, _, _ := f.send(t, http.MethodGet, "/protected", "", []*http.Cookie{access}); status == http.StatusOK {
		t.Fatal("expired access authorized")
	}
	f.issuer.mu.Lock()
	f.issuer.deactivated = true
	f.issuer.userInfoClaims["tenant"] = "two"
	f.issuer.userInfoClaims["roles"] = []string{"removed-upstream-role"}
	exchanges, userInfos := f.issuer.exchanges, f.issuer.userInfos
	f.issuer.mu.Unlock()
	f.restart()
	status, nextHeaders, data := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
	if status != http.StatusOK {
		t.Fatal("refresh after restart failed", status)
	}
	if strings.Contains(string(data), "access_token") || strings.Contains(string(data), "refresh_token") {
		t.Fatal("cookie refresh returned credentials")
	}
	next := providerRefreshCookie(t, nextHeaders, "AUTHP_REFRESH_TOKEN")
	nextAccess := providerRefreshCookie(t, nextHeaders, "oauth_portal_token")
	renewed := providerRefreshClaims(t, nextAccess)
	for _, key := range []string{"sub", "sid", "auth_time", "amr"} {
		if fmt.Sprint(claims[key]) != fmt.Sprint(renewed[key]) {
			t.Fatal("renewal changed original evidence", key)
		}
	}
	if claims["jti"] == renewed["jti"] || renewed["exp"].(float64) <= claims["exp"].(float64) || first.Value == next.Value {
		t.Fatal("credentials did not rotate")
	}
	if renewed["provider_name"] != claims["provider_name"] || renewed["provider_name"] != "OAuth User" {
		t.Fatal("custom transform lost captured provider attribute")
	}
	if !strings.Contains(fmt.Sprint(renewed["roles"]), "userinfo-user") || strings.Contains(fmt.Sprint(renewed["roles"]), "removed-upstream-role") {
		t.Fatal("snapshot mode observed new upstream roles")
	}
	f.issuer.mu.Lock()
	if f.issuer.exchanges != exchanges || f.issuer.userInfos != userInfos {
		t.Error("renewal contacted upstream")
	}
	f.issuer.mu.Unlock()
	if status, _, _ := f.send(t, http.MethodGet, "/protected", "", []*http.Cookie{nextAccess}); status != http.StatusOK {
		t.Fatal("renewed token did not authorize", status)
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{first}); status != http.StatusUnauthorized {
		t.Fatal("spent token admitted", status)
	}
	f.restart()
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{next}); status != http.StatusUnauthorized {
		t.Fatal("replay revocation lost at restart", status)
	}
	f.issuer.mu.Lock()
	f.issuer.deactivated = false
	f.issuer.mu.Unlock()
	_, headers = f.login(t, http.StatusSeeOther)
	fresh := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
	// Fresh login can replace its old family at capacity one.
	_, headers = f.login(t, http.StatusSeeOther)
	replacement := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{fresh}); status != http.StatusUnauthorized {
		t.Fatal("fresh-login replacement retained old family")
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/logout", "{}", nil); status != http.StatusOK {
		t.Fatal("logout failed", status)
	}
	f.restart()
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{replacement}); status != http.StatusUnauthorized {
		t.Fatal("logout lost at restart")
	}
}

func TestE2ETokenRefreshProviderSelection(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{unselected: true})
	_, headers := f.login(t, http.StatusSeeOther)
	if headers.Get("Authorization") == "" {
		t.Fatal("unselected provider did not retain access-only behavior")
	}
	for _, c := range (&http.Response{Header: headers}).Cookies() {
		if c.Name == "AUTHP_REFRESH_TOKEN" && c.Value != "" && c.MaxAge >= 0 {
			t.Fatal("unselected provider obtained refresh")
		}
	}
	for _, tc := range []struct {
		name    string
		edit    func(*authn.PortalConfig)
		message string
	}{
		{"missing mode", func(c *authn.PortalConfig) { c.RefreshTokens.ProviderRevalidation = nil }, "requires explicit OAuth snapshot mode"},
		{"store mode", func(c *authn.PortalConfig) {
			c.RefreshTokens.ProviderRevalidation = append(c.RefreshTokens.ProviderRevalidation, authn.TokenRefreshProviderConfig{Realm: "local", Mode: "snapshot"})
		}, "requires a provider realm"},
		{"duplicate provider", func(c *authn.PortalConfig) { c.IdentityProviders = append(c.IdentityProviders, "upstream") }, "exactly one renewal source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newProviderRefreshE2E(t, providerRefreshE2EOptions{edit: tc.edit, wantConfigError: tc.message})
		})
	}
}

func TestE2ETokenRefreshProviderPolicyDenial(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: []string{"match realm upstream", "deny"}})
	_, headers := f.login(t, http.StatusUnauthorized)
	for _, c := range (&http.Response{Header: headers}).Cookies() {
		if (c.Name == "oauth_portal_token" || c.Name == "AUTHP_REFRESH_TOKEN") && c.Value != "" && c.MaxAge >= 0 {
			t.Fatal("denied provider got credential")
		}
	}
}

func TestE2ETokenRefreshProviderRequestPolicy(t *testing.T) {
	for _, callback := range []bool{true, false} {
		t.Run(fmt.Sprintf("callback=%t", callback), func(t *testing.T) {
			matcher := "prefix match iss https://"
			if !callback {
				matcher = "regex match iss /auth/api/refresh_token$"
			}
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: []string{matcher, "require totp"}})
			if callback {
				f.login(t, http.StatusUnauthorized)
				return
			}
			_, headers := f.login(t, http.StatusSeeOther)
			first := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
			if status, headers, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusUnauthorized || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("current request policy did not deny provider renewal", status)
			}
			if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{first}); status != http.StatusUnauthorized {
				t.Fatal("denied family retained renewal authority", status)
			}
		})
	}
}

func TestE2ETokenRefreshProviderRequestClaims(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: []string{"match realm upstream", "add request_addr {claims.addr} as string", "add request_issuer {claims.iss} as string"}})
	_, headers := f.login(t, http.StatusSeeOther)
	claims := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
	if claims["request_addr"] != "127.0.0.1" || claims["request_issuer"] != f.server.URL+"/auth/oauth2/upstream/" {
		t.Fatal("callback did not transform current request metadata")
	}
	if status, headers, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusOK {
		t.Fatal("request-dependent transforms prevented renewal", status)
	} else {
		claims = providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
		if claims["request_addr"] != "127.0.0.1" || claims["request_issuer"] != f.server.URL+"/auth/api/refresh_token" || claims["iss"] != f.server.URL+"/auth" {
			t.Fatal("renewal reused callback context or changed the bound JWT issuer")
		}
	}
}

func TestE2ETokenRefreshProviderRoleAliases(t *testing.T) {
	for _, key := range []string{"role", "group", "groups", "realm_access", "app_metadata"} {
		t.Run(key, func(t *testing.T) {
			lines := []string{"match realm upstream", "action overwrite roles mapped"}
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: lines, wrapProvider: func(provider idp.IdentityProvider) idp.IdentityProvider {
				return &providerNestedRoleAdapter{IdentityProvider: provider, field: key}
			}})
			f.issuer.mu.Lock()
			f.issuer.userInfoClaims[key] = "retired"
			if key == "groups" {
				f.issuer.userInfoClaims[key] = []string{"retired"}
			}
			if key == "realm_access" {
				f.issuer.userInfoClaims[key] = map[string]any{"roles": []string{"retired"}, "tenant": "one"}
			}
			if key == "app_metadata" {
				f.issuer.userInfoClaims[key] = map[string]any{"authorization": map[string]any{"roles": []string{"retired"}}}
			}
			f.issuer.mu.Unlock()
			_, headers := f.login(t, http.StatusSeeOther)
			for step := range 2 {
				if step != 0 {
					var status int
					status, headers, _ = f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
					if status != http.StatusOK {
						t.Fatal("mapped provider could not renew", status)
					}
				}
				claims := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
				roles := fmt.Sprint(claims["roles"])
				if !strings.Contains(roles, "mapped") || strings.Contains(roles, "retired") {
					t.Fatal("signed roles restored a raw provider alias after transformation")
				}
				if status, _, _ := f.send(t, http.MethodGet, "/protected", "", nil); status != http.StatusOK {
					t.Fatal("mapped provider lost protected access", status)
				}
			}
		})
	}
}

// An embedding provider may map its verified UserInfo into the conventional
// root claim shape understood by user.NewUser. Keep the real provider's state,
// signature, nonce, PKCE and TLS exchange; expose only its verified payload.
type providerNestedRoleAdapter struct {
	idp.IdentityProvider
	field string
}

func (p *providerNestedRoleAdapter) Request(op operator.Type, rr *requests.Request) error {
	if err := p.IdentityProvider.Request(op, rr); err != nil {
		return err
	}
	if op == operator.Authenticate && rr.Response.Code == http.StatusOK && rr.Response.ReturnURLBound {
		if claims, ok := rr.Response.Payload.(map[string]any); ok {
			if info, ok := claims["userinfo"].(map[string]any); ok {
				if value, exists := info[p.field]; exists {
					claims[p.field] = value
				}
			}
		}
	}
	return nil
}

func TestE2ETokenRefreshProviderNestedRolePolicy(t *testing.T) {
	for _, key := range []string{"realm_access", "app_metadata"} {
		for _, callback := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/callback=%t", key, callback), func(t *testing.T) {
				lines := []string{"match roles privileged", "require totp"}
				if !callback {
					lines = append(lines, "regex match iss /auth/api/refresh_token$")
				}
				f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: lines, wrapProvider: func(provider idp.IdentityProvider) idp.IdentityProvider {
					return &providerNestedRoleAdapter{IdentityProvider: provider, field: key}
				}})
				value := map[string]any{"roles": []string{"privileged"}}
				if key == "app_metadata" {
					value = map[string]any{"authorization": value}
				}
				f.issuer.mu.Lock()
				f.issuer.userInfoClaims[key] = value
				f.issuer.mu.Unlock()
				if !callback {
					_, headers := f.login(t, http.StatusSeeOther)
					first := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
					status, headers, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
					if status != http.StatusUnauthorized || len(headers.Values("Set-Cookie")) != 0 {
						t.Fatal("nested roles bypassed the required renewal factor", status)
					}
					if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{first}); status != http.StatusUnauthorized {
						t.Fatal("denied provider retained renewal authority", status)
					}
					return
				}
				_, headers := f.login(t, http.StatusUnauthorized)
				for _, c := range (&http.Response{Header: headers}).Cookies() {
					if (c.Name == "oauth_portal_token" || c.Name == "AUTHP_REFRESH_TOKEN") && c.Value != "" && c.MaxAge >= 0 {
						t.Fatal("provider obtained credentials without the required factor")
					}
				}
			})
		}
	}

}

func TestE2ETokenRefreshProviderNestedRoles(t *testing.T) {
	for _, key := range []string{"realm_access", "app_metadata"} {
		t.Run(key, func(t *testing.T) {
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{persistent: true, wrapProvider: func(provider idp.IdentityProvider) idp.IdentityProvider {
				return &providerNestedRoleAdapter{IdentityProvider: provider, field: key}
			}})
			value := map[string]any{"roles": []string{"privileged"}, "access_token": "nested-provider-secret"}
			if key == "app_metadata" {
				value = map[string]any{"authorization": value}
			}
			f.issuer.mu.Lock()
			f.issuer.userInfoClaims[key] = value
			f.issuer.mu.Unlock()
			_, headers := f.login(t, http.StatusSeeOther)
			for step := range 2 {
				if step != 0 {
					f.issuer.mu.Lock()
					f.issuer.deactivated = true
					f.issuer.mu.Unlock()
					f.restart()
					var status int
					status, headers, _ = f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
					if status != http.StatusOK {
						t.Fatal("captured nested roles could not renew after restart", status)
					}
				}
				claims := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
				if !strings.Contains(fmt.Sprint(claims["roles"]), "privileged") {
					t.Fatal("signed access omitted verified nested roles")
				}
				if status, _, _ := f.send(t, http.MethodGet, "/protected", "", nil); status != http.StatusOK {
					t.Fatal("nested roles lost protected access", status)
				}
			}
		})
	}
}

func TestE2ETokenRefreshProviderCrossDevice(t *testing.T) {
	for _, requireFactor := range []bool{false, true} {
		t.Run(fmt.Sprintf("factor=%t", requireFactor), func(t *testing.T) {
			lines := []string{"regex match iss /cross-device/poll$"}
			if requireFactor {
				lines = append(lines, "match roles privileged", "require totp")
			} else {
				lines = append(lines, "action overwrite roles mapped")
			}
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: lines, edit: func(config *authn.PortalConfig) {
				crossDeviceConfig(t, config)
			}, wrapProvider: func(provider idp.IdentityProvider) idp.IdentityProvider {
				return &providerNestedRoleAdapter{IdentityProvider: provider, field: "realm_access"}
			}})
			f.issuer.mu.Lock()
			f.issuer.userInfoClaims["realm_access"] = map[string]any{"roles": []string{"privileged"}}
			f.issuer.mu.Unlock()
			approver := &oidcE2EFixture{server: f.server, client: f.client, issuer: f.server.URL + "/auth"}
			requester := crossDeviceBrowser(approver)
			interaction := crossDeviceStart(t, requester)
			crossDeviceBegin(t, approver, interaction)
			_, headers := f.login(t, http.StatusSeeOther)
			approverClaims := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
			confirmation := approver.request(t, http.MethodGet, "/cross-device/confirm", nil, nil)
			oidcE2EStatus(t, confirmation, http.StatusOK)
			oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
			// Normal rotation of the approving family keeps its approved transfer live.
			if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusOK {
				t.Fatal("approving provider could not renew", status)
			}
			poll := crossDevicePost(t, requester, "poll", crossDevicePollValues(interaction))
			f.assertNoProviderCredentials(t, poll.header, poll.body)
			if requireFactor {
				oidcE2EStatus(t, poll, http.StatusUnauthorized)
				if len(poll.header.Values("Set-Cookie")) != 0 {
					t.Fatal("factor-denied requester received credentials")
				}
				return
			}
			oidcE2EStatus(t, poll, http.StatusOK)
			claims := providerRefreshClaims(t, providerRefreshCookie(t, poll.header, "oauth_portal_token"))
			if fmt.Sprint(claims["amr"]) != "[federated]" || claims["auth_time"] != approverClaims["auth_time"] {
				t.Fatal("requester lost completed provider authentication evidence")
			}
			roles := fmt.Sprint(claims["roles"])
			if !strings.Contains(roles, "mapped") || strings.Contains(roles, "privileged") || claims["sid"] != nil {
				t.Fatal("requester bypassed current policy or inherited its approving family")
			}
			if loginIdentityCookie(requester, "AUTHP_REFRESH_TOKEN") != "" {
				t.Fatal("provider requester obtained a refresh credential")
			}
			response := requester.request(t, http.MethodGet, f.server.URL+"/protected", nil, nil)
			oidcE2EStatus(t, response, http.StatusOK)
		})
	}
}

type providerCompletionProbe struct {
	idp.IdentityProvider
	armed      atomic.Bool
	reads      atomic.Int32
	beforeDeny func()
}

func (p *providerCompletionProbe) Configured() bool {
	// Model a provider becoming unavailable between committed issuance and
	// cache reconstruction, while retaining the real TLS OAuth protocol.
	if p.armed.Load() {
		if reads := p.reads.Add(1); reads > 1 {
			if reads == 2 && p.beforeDeny != nil {
				p.beforeDeny()
			}
			return false
		}
	}
	return p.IdentityProvider.Configured()
}

func TestE2ETokenRefreshProviderRenewalCompletionCleanup(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup_fails=%t", cleanupFails), func(t *testing.T) {
			var probe *providerCompletionProbe
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{persistent: cleanupFails, wrapProvider: func(provider idp.IdentityProvider) idp.IdentityProvider {
				probe = &providerCompletionProbe{IdentityProvider: provider}
				return probe
			}})
			f.login(t, http.StatusSeeOther)
			want := http.StatusUnauthorized
			if cleanupFails {
				want = http.StatusServiceUnavailable
				probe.beforeDeny = func() {
					if err := f.closeState(); err != nil {
						t.Error(err)
					}
				}
			}
			probe.armed.Store(true)
			if status, headers, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != want || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("failed renewal completion delivered credentials or misclassified cleanup failure", status)
			}
			if cleanupFails {
				return
			}
			probe.armed.Store(false)
			// A new browser presents no previous credential that could evict the orphan.
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			f.client.Jar = jar
			f.login(t, http.StatusSeeOther)
		})
	}
}

func TestE2ETokenRefreshProviderConcurrentReplay(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{})
	_, headers := f.login(t, http.StatusSeeOther)
	first := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
	type exchange struct {
		status  int
		headers http.Header
	}
	exchanges := make(chan exchange, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			status, headers, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{first})
			exchanges <- exchange{status, headers}
		})
	}
	wg.Wait()
	close(exchanges)
	counts := map[int]int{}
	var descendant *http.Cookie
	for result := range exchanges {
		counts[result.status]++
		if result.status == http.StatusOK {
			descendant = providerRefreshCookie(t, result.headers, "AUTHP_REFRESH_TOKEN")
		}
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusUnauthorized] != 1 {
		t.Fatal("strict reuse was not one success and one denial", counts)
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{descendant}); status != http.StatusUnauthorized {
		t.Fatal("reuse did not revoke descendant")
	}
}

func TestE2ETokenRefreshProviderDeadlines(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(fmt.Sprintf("absolute=%t", absolute), func(t *testing.T) {
			options := providerRefreshE2EOptions{access: 1, idle: 2, absolute: 8}
			if absolute {
				options.idle = 3
				options.absolute = 4
			}
			f := newProviderRefreshE2E(t, options)
			_, headers := f.login(t, http.StatusSeeOther)
			claims := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
			if !absolute {
				cookie := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
				time.Sleep(time.Until(cookie.Expires) + 20*time.Millisecond)
				if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{cookie}); status != http.StatusUnauthorized {
					t.Fatal("idle expiry renewed")
				}
				return
			}
			// Authentication and admission can cross a clock-second boundary.
			// Read the actual family deadline from the public renewal metadata.
			status, _, data := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
			var metadata struct {
				AbsoluteExpiresAt int64 `json:"session_expires_at"`
			}
			if status != http.StatusOK || json.Unmarshal(data, &metadata) != nil || metadata.AbsoluteExpiresAt <= 0 {
				t.Fatal("missing absolute family deadline", status)
			}
			end := time.Unix(metadata.AbsoluteExpiresAt, 0)
			for time.Now().Before(end) {
				status, headers, data := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
				if status != http.StatusOK {
					if time.Now().Before(end) {
						t.Fatal("live family failed", status)
					}
					break
				}
				current := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
				if json.Unmarshal(data, &metadata) != nil || metadata.AbsoluteExpiresAt != end.Unix() || current["auth_time"] != claims["auth_time"] {
					t.Fatal("rotation changed the original deadline or authentication time")
				}
				if int64(current["exp"].(float64)) > end.Unix() {
					t.Fatal("access exceeded absolute deadline")
				}
				time.Sleep(min(time.Until(end)+20*time.Millisecond, 500*time.Millisecond))
			}
			if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusUnauthorized {
				t.Fatal("active family exceeded absolute deadline", status)
			}
		})
	}
}

func TestE2ETokenRefreshProviderEvidenceRejection(t *testing.T) {
	for _, kind := range []string{"missing subject", "oversized snapshot", "local challenge"} {
		t.Run(kind, func(t *testing.T) {
			options := providerRefreshE2EOptions{}
			if kind == "local challenge" {
				options.transforms = []string{"match realm upstream", "require auth challenges totp"}
			}
			f := newProviderRefreshE2E(t, options)
			f.issuer.mu.Lock()
			switch kind {
			case "missing subject":
				f.issuer.identityClaims["sub"] = ""
			case "oversized snapshot":
				f.issuer.userInfoClaims["padding"] = strings.Repeat("x", 32<<10)
			}
			f.issuer.mu.Unlock()
			_, headers := f.login(t, http.StatusUnauthorized)
			for _, c := range (&http.Response{Header: headers}).Cookies() {
				if (c.Name == "oauth_portal_token" || c.Name == "AUTHP_REFRESH_TOKEN") && c.Value != "" && c.MaxAge >= 0 {
					t.Fatal("rejected evidence issued credentials")
				}
			}
		})
	}
}

func TestE2ETokenRefreshProviderLocalReplacement(t *testing.T) {
	for _, excluded := range []bool{false, true} {
		t.Run(fmt.Sprintf("local access only=%t", excluded), func(t *testing.T) {
			f := newProviderRefreshE2E(t, providerRefreshE2EOptions{excludeLocal: excluded})
			_, headers := f.login(t, http.StatusSeeOther)
			old := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
			status, _, data := f.send(t, http.MethodPost, "/auth/login", `{"username":"keymember","realm":"local"}`, nil)
			if status != http.StatusOK {
				t.Fatal("local identification failed", status)
			}
			var begin struct {
				SandboxID     string `json:"sandbox_id"`
				SandboxSecret string `json:"sandbox_secret"`
			}
			if err := json.Unmarshal(data, &begin); err != nil || begin.SandboxID == "" {
				t.Fatal("missing local challenge")
			}
			body := oidcE2EJSON(t, map[string]any{"username": "keymember", "realm": "local", "sandbox_id": begin.SandboxID, "sandbox_secret": begin.SandboxSecret, "challenge_kind": "password", "challenge_response": tests.TestPwd1})
			status, headers, _ = f.send(t, http.MethodPost, "/auth/login", string(body), nil)
			if status != http.StatusOK {
				t.Fatal("local replacement failed", status)
			}
			if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", []*http.Cookie{old}); status != http.StatusUnauthorized {
				t.Fatal("local login retained provider authority")
			}
			if excluded {
				for _, c := range (&http.Response{Header: headers}).Cookies() {
					if c.Name == "AUTHP_REFRESH_TOKEN" && c.Value != "" && c.MaxAge >= 0 {
						t.Fatal("excluded local realm obtained family")
					}
				}
				return
			}
			access := providerRefreshCookie(t, headers, "oauth_portal_token")
			claims := providerRefreshClaims(t, access)
			if claims["sub"] != "keymember" || fmt.Sprint(claims["amr"]) != "[pwd]" {
				t.Fatal("mixed sources contaminated local proof")
			}
			if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusOK {
				t.Fatal("local replacement family unavailable")
			}
		})
	}
}

func TestE2ETokenRefreshProviderProfileBoundary(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{transforms: []string{"match realm upstream", "action add role authp/user"}, edit: func(c *authn.PortalConfig) { c.API = &authn.APIConfig{ProfileEnabled: true} }})
	f.login(t, http.StatusSeeOther)
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/profile", `{"kind":"fetch_user_api_keys"}`, nil); status != http.StatusNotImplemented {
		t.Fatal("provider session acquired local profile capability", status)
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusOK {
		t.Fatal("provider refresh failed")
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/profile", `{"kind":"fetch_user_api_keys"}`, nil); status != http.StatusNotImplemented {
		t.Fatal("renewal acquired local profile capability", status)
	}
}

func TestE2EOpenAPIContractProviderRefresh(t *testing.T) {
	validate, _ := openAPIContractValidators(t)
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{})
	_, headers := f.login(t, http.StatusSeeOther)
	validate(t, "/oauth2/{realm}/authorization-code-callback", "GET", http.StatusSeeOther, headers, nil)
	status, headers, body := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
	validate(t, "/api/refresh_token", "POST", status, headers, body)
	status, headers, body = f.send(t, http.MethodPost, "/auth/api/logout", "{}", nil)
	validate(t, "/api/logout", "POST", status, headers, body)
}
