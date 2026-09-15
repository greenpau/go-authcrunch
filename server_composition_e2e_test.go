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

package authcrunch_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	clientparser "github.com/greenpau/go-authcrunch/pkg/authclient/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	adminparser "github.com/greenpau/go-authcrunch/pkg/authn/admin_api/parser"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// This fixture models the downstream host entirely through public APIs. It owns
// tokenization, private persistence, HTTP mounting, and drain-before-disposal.
type serverCompositionFixture struct {
	server                                        *httptest.Server
	client                                        *http.Client
	mu                                            sync.RWMutex
	active                                        *authcrunch.Server
	origin, issuer, stateFile, usersFile, keyFile string
	body                                          []string
	cookies                                       []string
	configure                                     []func(*authcrunch.Config)
}

type compositionResponse struct {
	status int
	header http.Header
	body   []byte
}

func newServerCompositionFixture(t *testing.T, custom bool, configure ...func(*authcrunch.Config)) *serverCompositionFixture {
	t.Helper()
	dir := t.TempDir()
	f := &serverCompositionFixture{stateFile: filepath.Join(dir, "applications.json"), usersFile: filepath.Join(dir, "users.json"), keyFile: filepath.Join(dir, "oidc.pem")}
	f.configure = configure
	db, err := identity.NewDatabase(f.usersFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "admin"} {
		roles := []string{"authp/user"}
		if name == "admin" {
			roles = append(roles, "authp/admin")
		}
		if err := db.AddUser(&requests.Request{User: requests.User{Username: name, Email: name + "@example.test", Password: tests.TestPwd1, Roles: roles}}); err != nil {
			t.Fatal("provision composition identity")
		}
	}
	if err := oidc.GenerateSigningKeyFile(f.keyFile); err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		defer f.mu.RUnlock()
		if r.URL.Path == "/protected" {
			gate, err := f.active.GetGatekeeperByName("policy")
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			rr := requests.NewAuthorizationRequest()
			if err := gate.Authenticate(w, r, rr); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if rr.Response.Authorized {
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		portal, err := f.active.GetPortalByName("portal")
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("composition portal request failed")
		}
	}))
	f.origin = "https://" + f.server.Listener.Addr().String()
	f.issuer = f.origin + "/tenant/auth"
	if custom {
		f.cookies = []string{"cookie prefix COMPANY", "cookie oidc session id name WEB_OIDC_SESSION", "cookie refresh token name WEB_REFRESH"}
	}
	f.body = []string{"redirect_uri https://application.example.test/callback", "scopes openid profile email", "require_pkce on", "skip_consent on"}
	provisioned, err := oidcparser.NewOIDCClientConfigFromDirectives("website", f.body)
	if err != nil {
		t.Fatal(err)
	}
	app, err := oidc.NewOAuthApplicationConfig("website", provisioned)
	if err != nil {
		t.Fatal(err)
	}
	f.save(t, app)
	if _, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application website", f.body, nil); err == nil {
		t.Fatal("ordinary adaptation unexpectedly generated credentials")
	}
	f.replace(t, false, "")
	f.server.StartTLS()
	f.client = f.server.Client()
	f.client.Timeout = 10 * time.Second
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f.client.Jar, _ = cookiejar.New(nil)
	t.Cleanup(func() {
		f.server.Close()
		if err := f.active.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *serverCompositionFixture) save(t *testing.T, app *oidc.OAuthApplicationConfig) {
	t.Helper()
	data, err := json.Marshal(&authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{app}})
	if err != nil {
		t.Fatal("serialize application")
	}
	if err := os.WriteFile(f.stateFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(f.stateFile); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("registration file permissions")
	}
}

func (f *serverCompositionFixture) replace(t *testing.T, export bool, secret string) *oidc.ClientConfig {
	t.Helper()
	var saved authcrunch.Config
	if err := saved.LoadFromJSONFile(f.stateFile); err != nil {
		t.Fatal(err)
	}
	previous, err := saved.GetOAuthApplication("website")
	if err != nil {
		t.Fatal(err)
	}
	body := append([]string(nil), f.body...)
	if secret != "" {
		body = append(body, cfgutil.EncodeArgs([]string{"client_secret", secret}))
	}
	app, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application website", body, previous)
	if err != nil {
		t.Fatal(err)
	}
	if app.Client.ClientID != previous.Client.ClientID || (secret == "" && app.Client.ClientSecret != previous.Client.ClientSecret) {
		t.Fatal("adaptation changed credentials")
	}
	cfg := &authcrunch.Config{}
	for _, realm := range []string{"local", "excluded"} {
		cfg.IdentityStores = append(cfg.IdentityStores, &ids.IdentityStoreConfig{Name: realm, Kind: "local", Params: map[string]any{"realm": realm, "path": f.usersFile}})
	}
	portal := &authn.PortalConfig{API: &authn.APIConfig{ProfileEnabled: true}, Name: "portal", IdentityStores: []string{"local", "excluded"}, RawCryptoKeyStoreConfig: []string{"crypto key portal sign-verify from file testdata/rskeys/test_2_pri.pem"}}
	cookies, err := cookieparser.NewCookieConfigFromDirectives(f.cookies)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.ConfigureCookies(cookies); err != nil {
		t.Fatal(err)
	}
	adminLines := []string{"enable admin api"}
	if export {
		adminLines = append(adminLines, "enable admin api private key export")
	}
	admin, err := adminparser.NewAdminAPIConfigFromDirectives(adminLines)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.ConfigureAdminAPI(admin); err != nil {
		t.Fatal(err)
	}
	refresh, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"realms local", cfgutil.EncodeArgs([]string{"public", "origin", f.origin}), "base path /tenant/auth", "body transport enabled"})
	if err != nil {
		t.Fatal(err)
	}
	portal.RefreshTokens = refresh
	// Collect named applications before resolving provider references, even if
	// an embedding configuration encountered the portal block first.
	if err := cfg.AddOAuthApplication(app); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ConfigureOIDCProvider(portal, []string{cfgutil.EncodeArgs([]string{"issuer", f.issuer}), "realms local", cfgutil.EncodeArgs([]string{"signing", "key", "files", f.keyFile}), "applications website"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddAuthenticationPortal(portal); err != nil {
		t.Fatal(err)
	}
	cfg.AuthorizationPolicies = []*authz.PolicyConfig{{Name: "policy", ValidateBearerHeader: true, AuthRedirectDisabled: true, RawCryptoKeyStoreConfig: []string{"crypto key portal verify from file testdata/rskeys/test_2_pub.pem"}, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}}
	for _, configure := range f.configure {
		configure(cfg)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("serialize composition config")
	}
	var restored authcrunch.Config
	if json.Unmarshal(data, &restored) != nil {
		t.Fatal("restore composition config")
	}
	runtime, err := authcrunch.NewServer(&restored, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	old := f.active
	f.active = runtime
	f.mu.Unlock()
	if old != nil {
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f.save(t, app)
	return app.Client
}

func (f *serverCompositionFixture) request(t *testing.T, method, path, body string, headers http.Header) compositionResponse {
	t.Helper()
	target := path
	if strings.HasPrefix(path, "/") {
		target = f.issuer + path
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, headers)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal("composition HTTP request failed", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return compositionResponse{resp.StatusCode, resp.Header, data}
}

func compositionStatus(t *testing.T, r compositionResponse, want int) {
	t.Helper()
	if r.status != want {
		t.Fatalf("composition status %d, want %d", r.status, want)
	}
}

func (f *serverCompositionFixture) login(t *testing.T, realm, name string) {
	t.Helper()
	f.client.Jar, _ = cookiejar.New(nil)
	headers := http.Header{"Origin": {f.origin}, "Content-Type": {"application/x-www-form-urlencoded"}}
	start := f.request(t, http.MethodPost, "/login", url.Values{"realm": {realm}, "username": {name}}.Encode(), headers)
	compositionStatus(t, start, http.StatusSeeOther)
	target := start.header.Get("Location")
	password := f.request(t, http.MethodPost, target, url.Values{"secret": {tests.TestPwd1}}.Encode(), headers)
	compositionStatus(t, password, http.StatusSeeOther)
	compositionStatus(t, f.request(t, http.MethodGet, target, "", nil), http.StatusSeeOther)
}

func (f *serverCompositionFixture) native(t *testing.T, name string) *authclient.Credentials {
	t.Helper()
	cfg, err := clientparser.NewAuthenticationClientConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"base", "url", f.issuer}), "realm local", "username " + name, cfgutil.EncodeArgs([]string{"password", tests.TestPwd1}), "refresh transport body"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := authclient.NewClient(cfg, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil {
		t.Fatal("native composition login failed", err)
	}
	jar := f.client.Jar
	f.client.Jar = nil // Prove this credential independently of an existing browser login.
	compositionStatus(t, f.request(t, http.MethodGet, f.origin+"/protected", "", http.Header{"Authorization": {"Bearer " + credentials.AccessToken}}), http.StatusNoContent)
	f.client.Jar = jar
	return credentials
}

const compositionVerifier = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func (f *serverCompositionFixture) authorize(t *testing.T, client *oidc.ClientConfig) compositionResponse {
	t.Helper()
	digest := sha256.Sum256([]byte(compositionVerifier))
	form := url.Values{"client_id": {client.ClientID}, "redirect_uri": {client.RedirectURIs[0]}, "response_type": {"code"}, "scope": {"openid profile email"}, "state": {"composition-state"}, "nonce": {"composition-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
	return f.request(t, http.MethodGet, "/oidc/authorize?"+form.Encode(), "", nil)
}

func compositionCode(t *testing.T, response compositionResponse) string {
	t.Helper()
	compositionStatus(t, response, http.StatusFound)
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("state") != "composition-state" || location.Query().Get("code") == "" {
		t.Fatal("missing bound authorization code")
	}
	return location.Query().Get("code")
}

func (f *serverCompositionFixture) exchange(t *testing.T, client *oidc.ClientConfig, code, secret string) compositionResponse {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {compositionVerifier}}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client.ClientID)+":"+url.QueryEscape(secret)))}}
	return f.request(t, http.MethodPost, "/oidc/token", form.Encode(), headers)
}

func compositionJSON(t *testing.T, response compositionResponse) map[string]any {
	t.Helper()
	var value map[string]any
	if json.Unmarshal(response.body, &value) != nil {
		t.Fatal("invalid composition JSON")
	}
	return value
}

// Independently reconstruct RSA verification keys from the public HTTP JWKS.
func (f *serverCompositionFixture) verify(t *testing.T, raw, path string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("malformed composition JWT")
	}
	decode := func(value string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatal("invalid base64url")
		}
		return b
	}
	var header map[string]any
	if json.Unmarshal(decode(parts[0]), &header) != nil {
		t.Fatal("unexpected JWT algorithm")
	}
	response := f.request(t, http.MethodGet, path, "", nil)
	compositionStatus(t, response, http.StatusOK)
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if json.Unmarshal(response.body, &jwks) != nil || len(jwks.Keys) != 1 {
		t.Fatal("unexpected public keys")
	}
	key := jwks.Keys[0]
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if key[name] != "" {
			t.Fatal("private material in discovery")
		}
	}
	if key["kid"] != header["kid"] {
		t.Fatal("JWT key not published")
	}
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(decode(key["n"])), E: int(new(big.Int).SetBytes(decode(key["e"])).Int64())}
	hash := crypto.SHA256
	h := sha256.New()
	switch header["alg"] {
	case "RS256":
	case "RS384":
		hash = crypto.SHA384
		h = sha512.New384()
	case "RS512":
		hash = crypto.SHA512
		h = sha512.New()
	default:
		t.Fatal("unexpected JWT algorithm")
	}
	_, _ = h.Write([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(public, hash, h.Sum(nil), decode(parts[2])) != nil {
		t.Fatal("JWT signature invalid")
	}
	var claims map[string]any
	if json.Unmarshal(decode(parts[1]), &claims) != nil {
		t.Fatal("invalid JWT claims")
	}
	if claims["exp"].(float64) <= float64(time.Now().Unix()) {
		t.Fatal("expired JWT")
	}
	return claims
}

func TestE2EServerPublicConfigurationComposition(t *testing.T) {
	for _, custom := range []bool{false, true} {
		name := "defaults"
		if custom {
			name = "custom cookies"
		}
		t.Run(name, func(t *testing.T) {
			f := newServerCompositionFixture(t, custom)
			var saved authcrunch.Config
			if err := saved.LoadFromJSONFile(f.stateFile); err != nil {
				t.Fatal(err)
			}
			app, err := saved.GetOAuthApplication("website")
			if err != nil {
				t.Fatal(err)
			}
			client := app.Client
			discovery := f.request(t, http.MethodGet, "/.well-known/openid-configuration", "", nil)
			compositionStatus(t, discovery, http.StatusOK)
			if compositionJSON(t, discovery)["issuer"] != f.issuer {
				t.Fatal("issuer mount mismatch")
			}
			f.login(t, "local", "alice")
			cookieCfg, err := cookieparser.NewCookieConfigFromDirectives(f.cookies)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(f.issuer + "/oidc/authorize")
			found := map[string]bool{}
			for _, c := range f.client.Jar.Cookies(u) {
				found[c.Name] = true
			}
			if !found[cookieCfg.OIDCSessionIDCookieName] || !found[cookieCfg.RefreshTokenCookieName] {
				t.Fatal("effective cookie names not issued")
			}
			code := compositionCode(t, f.authorize(t, client))
			response := f.exchange(t, client, code, client.ClientSecret)
			compositionStatus(t, response, http.StatusOK)
			tokens := compositionJSON(t, response)
			claims := f.verify(t, tokens["id_token"].(string), "/oidc/jwks")
			if claims["iss"] != f.issuer || claims["aud"] != client.ClientID || claims["nonce"] != "composition-nonce" || claims["sub"] == "alice" {
				t.Fatal("OIDC identity binding")
			}
			subject := claims["sub"]
			access := tokens["access_token"].(string)
			info := f.request(t, http.MethodGet, "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + access}})
			compositionStatus(t, info, http.StatusOK)
			if compositionJSON(t, info)["email"] != "alice@example.test" {
				t.Fatal("userinfo identity")
			}
			pending := compositionCode(t, f.authorize(t, client))
			member := f.native(t, "alice")
			if member.RefreshToken == "" || member.SessionID == "" {
				t.Fatal("native credentials incomplete")
			}
			f.verify(t, member.AccessToken, "/.well-known/jwks.json")
			admin := f.native(t, "admin")
			f.client.Jar = nil // Authenticate API calls with their explicit bearer, not Alice's browser cookie.
			compositionStatus(t, f.request(t, http.MethodGet, "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + member.AccessToken}}), http.StatusUnauthorized)
			for _, token := range []string{access, tokens["id_token"].(string)} {
				r := f.request(t, http.MethodGet, f.origin+"/protected", "", http.Header{"Authorization": {"Bearer " + token}})
				compositionStatus(t, r, http.StatusUnauthorized)
			}

			for _, token := range []string{"", member.AccessToken, admin.AccessToken} {
				r := f.request(t, http.MethodGet, "/api/server/private_keys?format=jwk", "", http.Header{"Authorization": {"Bearer " + token}})
				if r.status == http.StatusOK || strings.Contains(string(r.body), "private_key") {
					t.Fatal("default disabled export returned material")
				}
			}
			// Same persisted credentials and key, fresh volatile runtime. Old opaque
			// grants/refresh credentials are intentionally not restored from Config.
			reloaded := f.replace(t, true, "")
			if reloaded.ClientID != client.ClientID || reloaded.ClientSecret != client.ClientSecret {
				t.Fatal("reload changed credentials")
			}
			compositionStatus(t, f.request(t, http.MethodGet, "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + access}}), http.StatusUnauthorized)
			compositionStatus(t, f.exchange(t, reloaded, pending, reloaded.ClientSecret), http.StatusBadRequest)
			nativeClient := *f.client
			nativeClient.Jar = nil
			original := f.client
			f.client = &nativeClient
			body, _ := json.Marshal(map[string]string{"refresh_token": member.RefreshToken})
			oldRefresh := f.request(t, http.MethodPost, "/api/refresh_token", string(body), http.Header{"Content-Type": {"application/json"}})
			f.client = original
			if oldRefresh.status == http.StatusOK {
				t.Fatal("old refresh credential survived volatile reload")
			}
			for _, token := range []string{"", member.AccessToken} {
				r := f.request(t, http.MethodGet, "/api/server/private_keys?format=jwk", "", http.Header{"Authorization": {"Bearer " + token}})
				if r.status == http.StatusOK || strings.Contains(string(r.body), "private_key") {
					t.Fatal("non-admin exported key")
				}
			}
			exported := f.request(t, http.MethodGet, "/api/server/private_keys?format=jwk", "", http.Header{"Authorization": {"Bearer " + admin.AccessToken}})
			compositionStatus(t, exported, http.StatusOK)
			if !strings.Contains(string(exported.body), "private_key") {
				t.Fatal("admin opt-in export missing")
			}
			f.login(t, "excluded", "alice")
			denied := f.authorize(t, reloaded)
			compositionStatus(t, denied, http.StatusFound)
			location, _ := url.Parse(denied.header.Get("Location"))
			if location.Query().Get("code") != "" || location.Query().Get("error") == "" {
				t.Fatal("excluded realm joined provider")
			}
			rotated := f.replace(t, true, oidc.GenerateClientSecret())
			f.login(t, "local", "alice")
			freshCode := compositionCode(t, f.authorize(t, rotated))
			compositionStatus(t, f.exchange(t, rotated, freshCode, client.ClientSecret), http.StatusUnauthorized)
			response = f.exchange(t, rotated, freshCode, rotated.ClientSecret)
			compositionStatus(t, response, http.StatusOK)
			newClaims := f.verify(t, compositionJSON(t, response)["id_token"].(string), "/oidc/jwks")
			if newClaims["sub"] != subject {
				t.Fatal("reload changed immutable subject")
			}
			cookieValue := func(name string) string {
				t.Helper()
				requestURL, err := url.Parse(f.issuer + "/")
				if err != nil {
					t.Fatal(err)
				}
				for _, cookie := range f.client.Jar.Cookies(requestURL) {
					if cookie.Name == name {
						return cookie.Value
					}
				}
				return ""
			}
			headers := http.Header{"Origin": {f.origin}, "Content-Type": {"application/json"}, "X-Authcrunch-Refresh": {"1"}}
			bootstrap := f.request(t, http.MethodPost, "/api/refresh_session", "{}", headers)
			compositionStatus(t, bootstrap, http.StatusOK)
			session := compositionJSON(t, bootstrap)["session_id"].(string)
			headers.Set("X-Authcrunch-Refresh-Session", session)
			previousRefresh := cookieValue(cookieCfg.RefreshTokenCookieName)
			refresh := f.request(t, http.MethodPost, "/api/refresh_token", "{}", headers)
			compositionStatus(t, refresh, http.StatusOK)
			metadata := compositionJSON(t, refresh)
			if metadata["session_id"] != session || metadata["access_token"] != nil || metadata["refresh_token"] != nil {
				t.Fatal("browser refresh metadata or credential isolation")
			}
			currentRefresh := cookieValue(cookieCfg.RefreshTokenCookieName)
			if currentRefresh == "" || currentRefresh == previousRefresh {
				t.Fatal("composed browser refresh did not rotate")
			}
			refreshedClaims := f.verify(t, cookieValue(cookieCfg.AccessTokenCookieName), "/.well-known/jwks.json")
			if refreshedClaims["sub"] != "alice" {
				t.Fatal("refresh changed portal identity")
			}
			compositionStatus(t, f.request(t, http.MethodGet, f.origin+"/protected", "", nil), http.StatusNoContent)
			headers.Del("X-Authcrunch-Refresh-Session") // The precondition belongs only to rotation.
			compositionStatus(t, f.request(t, http.MethodPost, "/api/logout", "{}", headers), http.StatusOK)
			for _, name := range []string{cookieCfg.AccessTokenCookieName, cookieCfg.RefreshTokenCookieName, cookieCfg.OIDCSessionIDCookieName} {
				if cookieValue(name) != "" {
					t.Fatal("logout retained a composed browser credential")
				}
			}
			compositionStatus(t, f.request(t, http.MethodGet, f.origin+"/protected", "", nil), http.StatusUnauthorized)
			headers.Set("Cookie", cookieCfg.RefreshTokenCookieName+"="+currentRefresh)
			compositionStatus(t, f.request(t, http.MethodPost, "/api/refresh_token", "{}", headers), http.StatusUnauthorized)
			newAccess := compositionJSON(t, response)["access_token"].(string)
			compositionStatus(t, f.request(t, http.MethodGet, "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + newAccess}}), http.StatusUnauthorized)
		})
	}
}
