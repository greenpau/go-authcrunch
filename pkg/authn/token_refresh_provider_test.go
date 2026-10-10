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

package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func TestTokenRefreshProviderSnapshot(t *testing.T) {
	input := map[string]any{"sub": "stable-subject", "roles": []string{"viewer"}, "custom": map[string]any{"tenant": "one", "number": json.Number("9007199254740993"), "ACCESS_TOKEN": "secret"}, "sid": "forged", "amr": []string{"mfa"}, "access_token": "secret", "refresh_token": "secret", "id_token": "secret", "client_secret": "secret"}
	data, err := encodeProviderSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("secret")) || bytes.Contains(data, []byte("forged")) {
		t.Fatal("snapshot retained credentials or proof")
	}
	claims, err := decodeProviderSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	custom := claims["custom"].(map[string]any)
	if custom["number"] != json.Number("9007199254740993") || custom["tenant"] != "one" {
		t.Fatal("custom claims lost precision")
	}
	claims["sub"] = "changed"
	input["roles"].([]string)[0] = "changed"
	again, err := decodeProviderSnapshot(data)
	if err != nil || again["sub"] != "stable-subject" || again["roles"].([]any)[0] != "viewer" {
		t.Fatal("snapshot aliases caller data")
	}
	if _, ok := input["access_token"]; !ok {
		t.Fatal("capture mutated input")
	}
	deep := map[string]any{"sub": "alice"}
	child := deep
	for range 18 {
		next := map[string]any{}
		child["nested"] = next
		child = next
	}
	for _, invalid := range []map[string]any{
		{"sub": "alice", "bad": "\xff"}, {"sub": "alice", "\xff": "value"}, {}, {"sub": 1}, {"sub": ""}, {"sub": "alice", "value": make(chan int)},
		{"sub": "alice", "value": math.NaN()}, {"sub": "alice", "value": strings.Repeat("x", tokenrefresh.MaxProviderSnapshotSize)},
		{"sub": "alice", "value": make([]any, 4096)}, deep,
		{"sub": "alice", "value": []string{strings.Repeat("x", 20000), strings.Repeat("y", 20000)}},
		{"sub": "alice", "value": json.Number(strings.Repeat("1", tokenrefresh.MaxProviderSnapshotSize))},
		{"sub": "alice", "app_metadata": map[string]any{"authorization": map[string]any{"roles": make([]any, 4096)}}},
	} {
		if data, err := encodeProviderSnapshot(invalid); !errors.Is(err, tokenrefresh.ErrDenied) || data != nil {
			t.Fatal("invalid evidence accepted")
		}
	}
	// A discarded credential does not exhaust the retained-content budget.
	if _, err := encodeProviderSnapshot(map[string]any{"sub": "alice", "access_token": strings.Repeat("secret", 10000)}); err != nil {
		t.Fatal("discarded credential entered snapshot limits", err)
	}
	for _, invalid := range []string{`null`, `{}`, `{"sub":"alice","sub":"bob"}`, `{"sub":"alice","access_token":"secret"}`, `{"sub":"alice"} {}`, ` {"sub":"alice"}`, `{"sub":3}`} {
		if _, err := decodeProviderSnapshot([]byte(invalid)); !errors.Is(err, tokenrefresh.ErrDenied) {
			t.Fatal("noncanonical evidence accepted")
		}
	}
}

func providerRefreshFixture(t *testing.T) *Portal {
	t.Helper()
	f := newRefreshPortal(t, true, false)
	p := f.portal
	p.refreshStore.Close()
	p.identityProviders = []idp.IdentityProvider{&mockIdentityProvider{name: "upstream", realm: "upstream", kind: "oauth", driver: "generic"}}
	p.config.RefreshTokens.Realms = []string{"local", "upstream"}
	p.config.RefreshTokens.ProviderRevalidation = []TokenRefreshProviderConfig{{Realm: "upstream", Mode: TokenRefreshProviderSnapshot}}
	p.config.RefreshTokens.MaxSessions = 1
	if err := p.configureRefresh(); err != nil {
		t.Fatal(err)
	}
	return p
}

func providerCallback(t *testing.T) (*http.Request, *requests.Request) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/oauth2/upstream/authorization-code-callback?code=once&state=bound", nil)
	rr := requests.NewRequest()
	rr.Upstream.Realm, rr.Upstream.Method = "upstream", "oauth2"
	rr.Upstream.BasePath, rr.Upstream.BaseURL, rr.Upstream.SessionID = "/auth", refreshTestOrigin, "fresh-session"
	rr.Response.Code, rr.Response.ReturnURLBound = http.StatusOK, true
	rr.Response.Payload = map[string]any{"sub": "alice", "email": "alice@example.test", "roles": []string{"authp/user"}}
	return r, rr
}

func TestTokenRefreshProviderIdentity(t *testing.T) {
	p := providerRefreshFixture(t)
	r, rr := providerCallback(t)
	u, first, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil {
		t.Fatal(err)
	}
	if u.Authenticator.Method != "oauth" || u.LoginEvidence != (requests.AuthenticationEvidence{}) || u.LoginUsername != "" || len(u.LoginMethods) != 0 {
		t.Fatal("provider acquired local proof")
	}
	u2, next, err := p.issueProviderRefresh(t.Context(), r, rr)
	if !errors.Is(err, tokenrefresh.ErrUnavailable) || u2 != nil || next != nil {
		t.Fatal("full store admitted independent login")
	}
	for _, edit := range []func(*tokenrefresh.Principal){
		func(v *tokenrefresh.Principal) { v.Source = "unknown" }, func(v *tokenrefresh.Principal) { v.Subject = "other" },
		func(v *tokenrefresh.Principal) { v.Backend = "other" }, func(v *tokenrefresh.Principal) { v.Realm = "local" },
		func(v *tokenrefresh.Principal) { v.BackendKind = "saml" }, func(v *tokenrefresh.Principal) { v.Methods = []string{"mfa"} },
		func(v *tokenrefresh.Principal) { v.Challenges = []string{"password:"} }, func(v *tokenrefresh.Principal) { v.ProviderSnapshot = []byte(`{}`) },
	} {
		v := first.Principal
		edit(&v)
		called := false
		err := (&portalRefreshAdapter{portal: p}).WithIdentity(t.Context(), v, func(map[string]any) error { called = true; return nil })
		if !errors.Is(err, tokenrefresh.ErrDenied) || called {
			t.Fatal("invalid provider identity reached issuance")
		}
	}
	r.AddCookie(&http.Cookie{Name: p.cookie.RefreshTokenCookieName, Value: first.RefreshToken})
	_, replacement, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil || replacement.SessionID == first.SessionID {
		t.Fatal("family replacement failed", err)
	}
	if _, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("old authority survived replacement")
	}
	p.identityProviders = nil
	if _, err := p.refresh.Refresh(t.Context(), replacement.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrDenied) {
		t.Fatal("removed provider renewed")
	}
}

func TestTokenRefreshProviderRequiresRedeemedCallback(t *testing.T) {
	p := providerRefreshFixture(t)
	for _, edit := range []func(*requests.Request){
		func(rr *requests.Request) { rr.Response.ReturnURLBound = false },
		func(rr *requests.Request) { rr.Response.Code = http.StatusFound },
		func(rr *requests.Request) { rr.Upstream.Method = "saml" },
	} {
		r, rr := providerCallback(t)
		edit(rr)
		if u, tokens, err := p.issueProviderRefresh(t.Context(), r, rr); !errors.Is(err, tokenrefresh.ErrDenied) || u != nil || tokens != nil {
			t.Fatal("unredeemed callback admitted")
		}
	}
}

func TestTokenRefreshProviderCallbackOrigin(t *testing.T) {
	p := providerRefreshFixture(t)
	for _, edit := range []func(*http.Request){
		func(r *http.Request) { r.TLS, r.URL.Scheme = nil, "http" },
		func(r *http.Request) { r.Host = "foreign.example.test" },
		func(r *http.Request) { r.URL.Path = "/foreign/callback" },
		func(r *http.Request) { r.URL.RawPath = "/auth/%6fauth2/upstream/callback" },
		func(r *http.Request) { r.Method = http.MethodPost },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example.test") },
		func(r *http.Request) { r.Header["Origin"] = []string{refreshTestOrigin, refreshTestOrigin} },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "cors") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "empty") },
	} {
		r, rr := providerCallback(t)
		edit(r)
		if u, tokens, err := p.issueProviderRefresh(t.Context(), r, rr); !errors.Is(err, tokenrefresh.ErrDenied) || u != nil || tokens != nil || rr.Response.Code != http.StatusForbidden {
			t.Fatal("invalid callback origin or navigation admitted")
		}
	}
	r, rr := providerCallback(t)
	r.Header.Set("Origin", refreshTestOrigin)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	if _, _, err := p.issueProviderRefresh(t.Context(), r, rr); err != nil {
		t.Fatal("bound cross-site navigation refused", err)
	}
}

func TestTokenRefreshProviderCompletionCleanup(t *testing.T) {
	p := providerRefreshFixture(t)
	r, rr := providerCallback(t)
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	record, err := storage.OpenRecord("session", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.sessions.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := p.authorizeProviderRefresh(t.Context(), w, r, rr); err == nil || rr.Response.Code != http.StatusServiceUnavailable {
		t.Fatal("failed completion did not fail closed")
	}
	if w.Header().Get("Authorization") != "" {
		t.Fatal("failed completion exposed bearer")
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("failed completion exposed cookie")
		}
	}
	_, tokens, err := p.issueProviderRefresh(t.Context(), r, rr)
	// The failed delivery freed the only family slot; reset callback outcome.
	if err == nil || tokens != nil {
		t.Fatal("failed callback reused")
	}
	rr.Response.Code = http.StatusOK
	_, tokens, err = p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil || tokens == nil {
		t.Fatal("failed delivery retained capacity", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.discardUndeliveredRefresh(ctx, tokens, tokenrefresh.CookieTransport); err != nil {
		t.Fatal("canceled request prevented cleanup", err)
	}
	if err := p.refresh.ValidateSession(context.Background(), tokens.SessionID, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("undelivered family live")
	}
	if tokens.Principal.AuthTime > time.Now().Unix() {
		t.Fatal("invalid auth time")
	}
}

func TestTokenRefreshProviderCurrentPolicy(t *testing.T) {
	p := providerRefreshFixture(t)
	r, rr := providerCallback(t)
	set := func(action string) {
		t.Helper()
		config, err := transformparser.NewUserTransformerConfigFromDirectives([]string{"match realm upstream", action})
		if err != nil {
			t.Fatal(err)
		}
		p.transformer, err = transformer.NewFactory([]*transformer.Config{config})
		if err != nil {
			t.Fatal(err)
		}
	}
	set("action add role first")
	_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil {
		t.Fatal(err)
	}
	set("action add role current")
	next, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	roles := strings.Join(next.Claims["roles"].([]string), " ")
	if !strings.Contains(roles, "current") || strings.Contains(roles, "first") {
		t.Fatal("renewal reused transformed output")
	}
	set("deny")
	if _, err := p.refresh.Refresh(t.Context(), next.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrDenied) {
		t.Fatal("current transform denial ignored")
	}
	if err := p.refresh.ValidateSession(t.Context(), next.SessionID, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("policy denial did not revoke")
	}
}

func TestTokenRefreshProviderRequestPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, matcher string
		callback      bool
	}{
		{"callback issuer", "prefix match iss " + refreshTestOrigin + "/auth/oauth2/", true},
		{"refresh issuer", "exact match iss " + refreshTestOrigin + "/auth/api/refresh_token", false},
		{"changed refresh address", "exact match addr 198.51.100.10", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := providerRefreshFixture(t)
			config, err := transformparser.NewUserTransformerConfigFromDirectives([]string{tc.matcher, "require totp"})
			if err != nil {
				t.Fatal(err)
			}
			p.transformer, err = transformer.NewFactory([]*transformer.Config{config})
			if err != nil {
				t.Fatal(err)
			}
			r, rr := providerCallback(t)
			// Upstream metadata cannot replace the current portal request's issuer.
			rr.Response.Payload.(map[string]any)["iss"] = "https://upstream.example.test"
			_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
			if tc.callback {
				if !errors.Is(err, tokenrefresh.ErrDenied) || first != nil {
					t.Fatal("callback ignored its current request's factor requirement", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r = httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/refresh_token", nil)
			r.RemoteAddr = "198.51.100.10:1234"
			ctx := context.WithValue(t.Context(), refreshRequestContextKey{}, r)
			if _, err := p.refresh.Refresh(ctx, first.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrDenied) {
				t.Fatal("renewal ignored its current request's factor requirement", err)
			}
			if err := p.refresh.ValidateSession(t.Context(), first.SessionID, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
				t.Fatal("current policy denial left the family live", err)
			}
		})
	}
}

func TestTokenRefreshProviderRoleAliases(t *testing.T) {
	for _, key := range []string{"role", "group", "groups", "realm_access", "app_metadata"} {
		t.Run(key, func(t *testing.T) {
			p := providerRefreshFixture(t)
			lines := []string{"match realm upstream", "action overwrite roles mapped"}
			config, err := transformparser.NewUserTransformerConfigFromDirectives(lines)
			if err != nil {
				t.Fatal(err)
			}
			p.transformer, err = transformer.NewFactory([]*transformer.Config{config})
			if err != nil {
				t.Fatal(err)
			}
			r, rr := providerCallback(t)
			claims := rr.Response.Payload.(map[string]any)
			claims[key] = "retired"
			if key == "groups" {
				claims[key] = []string{"retired"}
			}
			if key == "realm_access" {
				claims[key] = map[string]any{"roles": []string{"retired"}, "tenant": "one"}
			}
			if key == "app_metadata" {
				claims[key] = map[string]any{"authorization": map[string]any{"roles": []string{"retired"}}}
			}
			_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
			if err != nil {
				t.Fatal(err)
			}
			next, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport)
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range []*tokenrefresh.Result{first, next} {
				roles := strings.Join(result.Claims["roles"].([]string), " ")
				if !strings.Contains(roles, "mapped") || strings.Contains(roles, "retired") {
					t.Fatal("raw provider role alias undid the current transformation")
				}
			}
		})
	}
}

func TestTokenRefreshProviderNestedRolePolicy(t *testing.T) {
	for _, key := range []string{"realm_access", "app_metadata"} {
		for _, callback := range []bool{true, false} {
			t.Run(key+"/callback="+strconv.FormatBool(callback), func(t *testing.T) {
				p := providerRefreshFixture(t)
				lines := []string{"match roles privileged", "require totp"}
				if !callback {
					lines = append(lines, "regex match iss /auth/api/refresh_token$")
				}
				config, err := transformparser.NewUserTransformerConfigFromDirectives(lines)
				if err != nil {
					t.Fatal(err)
				}
				p.transformer, err = transformer.NewFactory([]*transformer.Config{config})
				if err != nil {
					t.Fatal(err)
				}
				r, rr := providerCallback(t)
				value := map[string]any{"roles": []string{"privileged"}}
				if key == "app_metadata" {
					value = map[string]any{"authorization": value}
				}
				rr.Response.Payload.(map[string]any)[key] = value
				_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
				if callback {
					if !errors.Is(err, tokenrefresh.ErrDenied) || first != nil {
						t.Fatal("nested provider roles bypassed the required factor")
					}
					return
				}
				if err != nil {
					t.Fatal("callback unexpectedly required the renewal-only factor", err)
				}
				r = httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/refresh_token", nil)
				ctx := context.WithValue(t.Context(), refreshRequestContextKey{}, r)
				if tokens, err := p.refresh.Refresh(ctx, first.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrDenied) || tokens != nil {
					t.Fatal("nested provider roles bypassed the renewal factor")
				}
				if err := p.refresh.ValidateSession(t.Context(), first.SessionID, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
					t.Fatal("denied provider retained family authority")
				}
			})
		}
	}
}

func TestTokenRefreshProviderNestedRoles(t *testing.T) {
	for _, key := range []string{"realm_access", "app_metadata"} {
		t.Run(key, func(t *testing.T) {
			p := providerRefreshFixture(t)
			r, rr := providerCallback(t)
			roles := []string{"privileged"}
			contribution := map[string]any{"roles": roles, "access_token": "discarded-secret"}
			value := contribution
			if key == "app_metadata" {
				value = map[string]any{"authorization": contribution}
			}
			rr.Response.Payload.(map[string]any)[key] = value
			_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
			if err != nil {
				t.Fatal(err)
			}
			roles[0] = "changed-after-capture"
			next, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport)
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range []*tokenrefresh.Result{first, next} {
				if !slices.Contains(result.Claims["roles"].([]string), "privileged") || bytes.Contains(result.Principal.ProviderSnapshot, []byte("discarded-secret")) {
					t.Fatal("snapshot lost verified nested roles or retained credentials")
				}
			}
			if contribution["access_token"] != "discarded-secret" {
				t.Fatal("capture mutated provider claims")
			}
		})
	}
}

func TestTokenRefreshProviderCrossDevice(t *testing.T) {
	for _, requireFactor := range []bool{false, true} {
		t.Run(strconv.FormatBool(requireFactor), func(t *testing.T) {
			p := providerRefreshFixture(t)
			lines := []string{"regex match iss /cross-device/poll$"}
			if requireFactor {
				lines = append(lines, "match roles privileged", "require totp")
			} else {
				lines = append(lines, "action overwrite roles mapped")
			}
			config, err := transformparser.NewUserTransformerConfigFromDirectives(lines)
			if err != nil {
				t.Fatal(err)
			}
			p.transformer, err = transformer.NewFactory([]*transformer.Config{config})
			if err != nil {
				t.Fatal(err)
			}
			r, rr := providerCallback(t)
			rr.Response.Payload.(map[string]any)["realm_access"] = map[string]any{"roles": []string{"privileged"}}
			u, tokens, err := p.issueProviderRefresh(t.Context(), r, rr)
			if err != nil {
				t.Fatal(err)
			}
			proof := &crossDeviceProof{user: u, expires: u.Claims.ExpiresAt, refreshSessionID: tokens.SessionID, providerClaims: tokens.Principal.ProviderSnapshot, providerMethod: "oauth2"}
			r = httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/cross-device/poll", nil)
			rr.Upstream.SessionID = "independent-requester"
			issued, err := p.issueCrossDeviceProvider(t.Context(), r, rr, proof)
			if requireFactor {
				if err == nil || issued != nil {
					t.Fatal("requester bypassed its nested-role factor policy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(issued.Claims.AuthenticationMethods, []string{"federated"}) || issued.AsMap()["auth_time"] != tokens.Claims["auth_time"] {
				t.Fatal("requester lost verified provider authentication evidence")
			}
			if !issued.HasRole("mapped") || issued.HasRole("privileged") || issued.AsMap()["sid"] != nil || issued.LoginEvidence.UserID != "" {
				t.Fatal("requester bypassed current policy or gained renewable/local proof")
			}
		})
	}
}

func TestTokenRefreshProviderRequestClaims(t *testing.T) {
	p := providerRefreshFixture(t)
	config, err := transformparser.NewUserTransformerConfigFromDirectives([]string{"match realm upstream", "add request_addr {claims.addr} as string", "add request_issuer {claims.iss} as string"})
	if err != nil {
		t.Fatal(err)
	}
	p.transformer, err = transformer.NewFactory([]*transformer.Config{config})
	if err != nil {
		t.Fatal(err)
	}
	r, rr := providerCallback(t)
	r.RemoteAddr = "192.0.2.1:1234"
	u, first, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil {
		t.Fatal("request claims lost during callback completion", err)
	}
	if first.Claims["request_addr"] != "192.0.2.1" || first.Claims["request_issuer"] != refreshTestOrigin+"/auth/oauth2/upstream/" || u == nil {
		t.Fatal("callback transforms did not receive current request metadata")
	}
	r = httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/refresh_token", nil)
	r.RemoteAddr = "198.51.100.10:1234"
	ctx := context.WithValue(t.Context(), refreshRequestContextKey{}, r)
	next, err := p.refresh.Refresh(ctx, first.RefreshToken, tokenrefresh.CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.userFromRefresh(ctx, next); err != nil {
		t.Fatal("request claims lost during renewal completion", err)
	}
	if next.Claims["request_addr"] != "198.51.100.10" || next.Claims["request_issuer"] != refreshTestOrigin+r.URL.Path || next.Claims["iss"] != refreshTestOrigin+"/auth" {
		t.Fatal("renewal reused login context or changed the bound JWT issuer")
	}
}

type providerCompletionIdentity struct {
	tokenrefresh.Identity
	after func()
}

func (i *providerCompletionIdentity) WithIdentity(ctx context.Context, principal tokenrefresh.Principal, apply func(map[string]any) error) error {
	err := i.Identity.WithIdentity(ctx, principal, apply)
	if err == nil {
		i.after()
	}
	return err
}

func TestTokenRefreshProviderRenewalCompletionCleanup(t *testing.T) {
	p := providerRefreshFixture(t)
	r, rr := providerCallback(t)
	_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	adapter := &portalRefreshAdapter{portal: p}
	identity := &providerCompletionIdentity{Identity: adapter, after: cancel}
	p.refresh, err = tokenrefresh.NewManager(p.refreshStore, identity, adapter, tokenrefresh.Policy{AccessLifetime: time.Minute, IdleTimeout: 2 * time.Minute, AbsoluteTimeout: 4 * time.Minute}, tokenrefresh.Binding{Portal: p.config.Name, Origin: refreshTestOrigin, BasePath: "/auth"})
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/refresh_token", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", refreshTestOrigin)
	r.Header.Set(refreshRequestHeader, "1")
	r.AddCookie(&http.Cookie{Name: p.cookie.RefreshTokenCookieName, Value: first.RefreshToken})
	w := httptest.NewRecorder()
	if err := p.handleAPIRefreshToken(ctx, w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusServiceUnavailable || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Authorization") != "" {
		t.Fatal("failed renewal completion delivered credentials or an invalid status")
	}
	if err := p.refresh.ValidateSession(t.Context(), first.SessionID, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("canceled completion left an undelivered family live", err)
	}
}

func TestTokenRefreshProviderErrorClassification(t *testing.T) {
	p := providerRefreshFixture(t)
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"denied", tokenrefresh.ErrDenied, http.StatusUnauthorized},
		{"invalid", tokenrefresh.ErrInvalid, http.StatusUnauthorized},
		{"unavailable", tokenrefresh.ErrUnavailable, http.StatusServiceUnavailable},
		{"denial and failed cleanup", errors.Join(tokenrefresh.ErrDenied, tokenrefresh.ErrUnavailable), http.StatusServiceUnavailable},
		{"invalid and failed cleanup", errors.Join(tokenrefresh.ErrInvalid, tokenrefresh.ErrUnavailable), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := p.refreshError(t.Context(), w, tc.err); err != nil || w.Code != tc.status {
				t.Fatal("incorrect refresh error classification", w.Code, err)
			}
		})
	}
}

func TestTokenRefreshProviderTrustBinding(t *testing.T) {
	p := providerRefreshFixture(t)
	r, rr := providerCallback(t)
	_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(first.Principal)
	if err != nil || string(data) != "{}" {
		t.Fatal("provider proof serialized publicly")
	}
	p.identityProviders[0].(*mockIdentityProvider).driver = "github"
	if _, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrDenied) {
		t.Fatal("provider trust change accepted captured evidence")
	}
}

func TestTokenRefreshProviderRealmWiring(t *testing.T) {
	for _, kind := range []string{"store/provider collision", "duplicate provider", "unsupported provider", "identity cookie"} {
		t.Run(kind, func(t *testing.T) {
			p := providerRefreshFixture(t)
			candidate := &mockIdentityProvider{name: "upstream", realm: "upstream", kind: "oauth", driver: "generic"}
			p.identityProviders = []idp.IdentityProvider{candidate}
			switch kind {
			case "store/provider collision":
				candidate.realm = "local"
			case "duplicate provider":
				p.identityProviders = append(p.identityProviders, candidate)
			case "unsupported provider":
				candidate.kind = "saml"
			case "identity cookie":
				candidate.identityTokenCookieName = "UPSTREAM_IDENTITY"
			}
			if err := p.configureRefresh(); err == nil {
				t.Fatal("invalid renewal source accepted")
			}
		})
	}
}

type providerFailureSigner struct {
	tokenrefresh.Signer
	fail bool
}

func (s *providerFailureSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	if s.fail {
		return "", tokenrefresh.ErrUnavailable
	}
	return s.Signer.Sign(ctx, claims)
}

func TestTokenRefreshProviderSigningFailure(t *testing.T) {
	p := providerRefreshFixture(t)
	adapter := &portalRefreshAdapter{portal: p}
	signer := &providerFailureSigner{Signer: adapter, fail: true}
	var err error
	p.refresh, err = tokenrefresh.NewManager(p.refreshStore, adapter, signer, tokenrefresh.Policy{AccessLifetime: time.Minute, IdleTimeout: 2 * time.Minute, AbsoluteTimeout: 4 * time.Minute}, tokenrefresh.Binding{Portal: p.config.Name, Origin: p.config.RefreshTokens.PublicOrigin, BasePath: "/auth"})
	if err != nil {
		t.Fatal(err)
	}
	r, rr := providerCallback(t)
	if _, tokens, err := p.issueProviderRefresh(t.Context(), r, rr); !errors.Is(err, tokenrefresh.ErrUnavailable) || tokens != nil {
		t.Fatal("failed signing admitted family")
	}
	signer.fail = false
	_, first, err := p.issueProviderRefresh(t.Context(), r, rr)
	if err != nil {
		t.Fatal("signing failure retained capacity", err)
	}
	signer.fail = true
	if _, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("failed signing published renewal")
	}
	signer.fail = false
	if _, err := p.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.CookieTransport); err != nil {
		t.Fatal("failed signing spent credential", err)
	}
}
