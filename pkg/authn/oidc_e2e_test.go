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
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const oidcE2ESecret = "oidc-test-client-secret-at-least-32-bytes"
const oidcE2EVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const oidcE2EChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

type oidcE2EFixture struct {
	server           *httptest.Server
	client           *http.Client
	issuer, callback string
	close            func()
}

type oidcE2EResponse struct {
	status int
	header http.Header
	body   []byte
}

func newOIDCE2EFixture(t *testing.T, mount string, refresh bool, cookieConfigs ...*cookie.Config) *oidcE2EFixture {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	issuer := "https://" + server.Listener.Addr().String() + mount
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal("could not provision OIDC user")
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "admin", Email: "admin@example.test", Password: tests.TestPwd1, Roles: []string{"authp/admin"}}}); err != nil {
		t.Fatal("could not provision OIDC administrator")
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "mfauser", Email: "mfa@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal("could not provision MFA user")
	}
	if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "mfauser", Email: "mfa@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "E2E", Secret: "0123456789abcdef0123456789abcdef", Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}}); err != nil {
		t.Fatal("could not provision MFA factor")
	}
	portalConfig := &authn.PortalConfig{Name: "oidc-e2e", CookieConfig: cookie.NewConfig(), API: &authn.APIConfig{AdminEnabled: true, ProfileEnabled: true}, IdentityStores: []string{"oidc-local"}, OIDCProvider: &authn.OIDCProviderConfig{Enabled: true, Issuer: issuer, Realms: []string{"local"}, SigningKeyFiles: []string{"../../testdata/rskeys/test_2_pri.pem"}, Clients: []*authn.OIDCClientConfig{
		{ClientID: "basic", ClientSecret: oidcE2ESecret, RedirectURIs: []string{"https://rp.example.test/callback?registered=yes"}},
		{ClientID: "second", ClientSecret: oidcE2ESecret, RedirectURIs: []string{"https://rp.example.test/callback?registered=yes"}, SkipConsent: true},
		{ClientID: "post", ClientSecret: oidcE2ESecret, TokenEndpointAuthMethod: "client_secret_post", RedirectURIs: []string{"https://rp.example.test/callback?registered=yes"}, SkipConsent: true},
		{ClientID: "public", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://rp.example.test/callback?registered=yes"}, SkipConsent: true},
	}}}
	if len(cookieConfigs) != 0 {
		portalConfig.CookieConfig = cookieConfigs[0]
	}
	if refresh {
		portalConfig.RefreshTokens = &authn.RefreshConfig{Enabled: true, PublicOrigin: "https://" + server.Listener.Addr().String(), BasePath: mount, Realms: []string{"local"}, BodyTransportEnabled: true}
	}
	config := &authcrunch.Config{IdentityStores: []*ids.IdentityStoreConfig{{Name: "oidc-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}}, AuthenticationPortals: []*authn.PortalConfig{portalConfig}}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authcrunch.Config
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	runtime, err := authcrunch.NewServer(&decoded, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	portal, err := runtime.GetPortalByName("oidc-e2e")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("OIDC portal request failed")
		}
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &oidcE2EFixture{server: server, client: client, issuer: issuer, callback: "https://rp.example.test/callback?registered=yes"}
	f.close = func() { server.Close(); portal.Close() }
	t.Cleanup(f.close)
	return f
}

func TestE2EOIDCIssuerMount(t *testing.T) {
	f := newOIDCE2EFixture(t, "/tenant/auth", false)
	f.loginJSON(t)
	code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
	for _, prefix := range []string{"", "/other", "/tenant/authentication"} {
		for _, endpoint := range []string{"/.well-known/openid-configuration", "/oidc/jwks", "/oidc/token"} {
			t.Run(prefix+endpoint, func(t *testing.T) {
				method := "GET"
				var form url.Values
				headers := make(http.Header)
				if endpoint == "/oidc/token" {
					method = "POST"
					form = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.callback}, "code_verifier": {oidcE2EVerifier}}
					headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("second:"+oidcE2ESecret)))
				}
				response := f.request(t, method, f.server.URL+prefix+endpoint, form, headers)
				var body map[string]any
				_ = json.Unmarshal(response.body, &body)
				if body["issuer"] != nil || body["keys"] != nil || body["access_token"] != nil {
					t.Fatal("OIDC endpoint served outside its issuer mount")
				}
			})
		}
	}
	// Requests outside the issuer mount must not consume the authorization code.
	tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
	f.verifyIDToken(t, tokens, "second")
}

func (f *oidcE2EFixture) request(t *testing.T, method, target string, form url.Values, headers http.Header) oidcE2EResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.issuer + target
	}
	r, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	maps.Copy(r.Header, headers)
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal("OIDC HTTP request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal("OIDC response read failed")
	}
	return oidcE2EResponse{status: response.StatusCode, header: response.Header, body: body}
}

func oidcE2EStatus(t *testing.T, r oidcE2EResponse, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("HTTP %d, expected %d", r.status, status)
	}
}

func (f *oidcE2EFixture) authorization(client string) url.Values {
	return url.Values{"client_id": {client}, "redirect_uri": {f.callback}, "response_type": {"code"}, "scope": {"openid profile email"}, "state": {"state & symbols=+"}, "nonce": {"nonce + exact"}, "code_challenge": {oidcE2EChallenge}, "code_challenge_method": {"S256"}}
}

func (f *oidcE2EFixture) loginBrowser(t *testing.T) oidcE2EResponse {
	t.Helper()
	origin := http.Header{"Origin": {f.server.URL}}
	start := f.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
	oidcE2EStatus(t, start, 303)
	sandbox := start.header.Get("Location")
	password := f.request(t, "POST", sandbox, url.Values{"secret": {tests.TestPwd1}}, origin)
	oidcE2EStatus(t, password, 303)
	completed := f.request(t, "GET", sandbox, nil, nil)
	oidcE2EStatus(t, completed, 303)
	return completed
}

func (f *oidcE2EFixture) loginJSON(t *testing.T) {
	t.Helper()
	client, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", Username: "alice", Password: tests.TestPwd1}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil || credentials == nil || credentials.AccessToken == "" {
		t.Fatal("OIDC real JSON login failed")
	}
}

func TestE2EOIDCFreshLoginRejectsEarlierCheckpoint(t *testing.T) {
	for _, parameter := range []string{"prompt", "max_age"} {
		t.Run(parameter, func(t *testing.T) {
			f := newOIDCE2EFixture(t, "/auth", false)
			origin := http.Header{"Origin": {f.server.URL}}
			start := f.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
			oidcE2EStatus(t, start, 303)
			sandbox := start.header.Get("Location")
			oidcE2EStatus(t, f.request(t, "POST", sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), 303)
			// Leave the verified checkpoint unredeemed until a later NumericDate.
			time.Sleep(1100 * time.Millisecond)
			params := f.authorization("second")
			if parameter == "prompt" {
				params.Set("prompt", "login")
			} else {
				params.Set("max_age", "0")
			}
			oidcE2EStatus(t, f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil), 303)
			oidcE2EStatus(t, f.request(t, "GET", sandbox, nil, nil), 303)
			response := f.request(t, "GET", "/oidc/continue", nil, nil)
			target, _ := url.Parse(response.header.Get("Location"))
			if target.Query().Get("error") != "login_required" || target.Query().Get("code") != "" {
				t.Fatal("earlier password checkpoint satisfied fresh authentication")
			}
			// A newly verified password can still complete the same request.
			f.loginBrowser(t)
			code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/continue", nil, nil))
			f.verifyIDToken(t, oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier)), "second")
		})
	}
}

func oidcProviderE2ECode(t *testing.T, r oidcE2EResponse) string {
	t.Helper()
	oidcE2EStatus(t, r, 302)
	u, err := url.Parse(r.header.Get("Location"))
	if err != nil {
		t.Fatal("invalid callback URI")
	}
	if u.Query().Get("code") == "" || u.Query().Get("error") != "" {
		t.Fatalf("code not returned, error %q", u.Query().Get("error"))
	}
	if u.Query().Get("registered") != "yes" || u.Query().Get("state") != "state & symbols=+" {
		t.Fatal("callback query or state changed")
	}
	return u.Query().Get("code")
}

func (f *oidcE2EFixture) exchange(t *testing.T, client, code, verifier string) oidcE2EResponse {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.callback}, "code_verifier": {verifier}}
	headers := http.Header{}
	switch client {
	case "post":
		form.Set("client_id", client)
		form.Set("client_secret", oidcE2ESecret)
	case "public":
		form.Set("client_id", client)
	default:
		form.Set("client_id", client)
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client)+":"+url.QueryEscape(oidcE2ESecret))))
	}
	return f.request(t, "POST", "/oidc/token", form, headers)
}

func oidcE2ETokens(t *testing.T, r oidcE2EResponse) map[string]any {
	t.Helper()
	oidcE2EStatus(t, r, 200)
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
		t.Fatal("token response cache policy missing")
	}
	var tokens map[string]any
	if err := json.Unmarshal(r.body, &tokens); err != nil {
		t.Fatal("invalid token JSON")
	}
	if tokens["token_type"] != "Bearer" || tokens["access_token"] == "" || tokens["id_token"] == "" {
		t.Fatal("token response missing fields")
	}
	if _, ok := tokens["refresh_token"]; ok {
		t.Fatal("unadvertised refresh token returned")
	}
	return tokens
}

// Verify signatures independently with crypto/rsa and fetched public JWKS;
// no production token parser, signing key, or portal internals are used.
func (f *oidcE2EFixture) verifyIDToken(t *testing.T, tokens map[string]any, client string) map[string]any {
	t.Helper()
	raw, ok := tokens["id_token"].(string)
	if !ok {
		t.Fatal("missing ID token")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("malformed ID token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal("malformed JWT header")
	}
	var header map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || header["alg"] != "RS256" {
		t.Fatal("unexpected ID signing algorithm")
	}
	jwks := f.request(t, "GET", "/oidc/jwks", nil, nil)
	oidcE2EStatus(t, jwks, 200)
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if json.Unmarshal(jwks.body, &set) != nil {
		t.Fatal("invalid JWKS")
	}
	var public *rsa.PublicKey
	for _, key := range set.Keys {
		for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
			if key[secret] != "" {
				t.Fatal("private key published")
			}
		}
		if key["kid"] != header["kid"] {
			continue
		}
		n, e := new(big.Int), new(big.Int)
		nb, _ := base64.RawURLEncoding.DecodeString(key["n"])
		eb, _ := base64.RawURLEncoding.DecodeString(key["e"])
		public = &rsa.PublicKey{N: n.SetBytes(nb), E: int(e.SetBytes(eb).Int64())}
	}
	if public == nil {
		t.Fatal("signing key absent from JWKS")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal("invalid signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("ID signature did not verify")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		t.Fatal("invalid ID claims")
	}
	if claims["iss"] != f.issuer || claims["aud"] != client || claims["nonce"] != "nonce + exact" || claims["sub"] == "alice" || claims["sub"] == "" {
		t.Fatal("incorrect ID token binding")
	}
	now := time.Now().Unix()
	if claims["exp"].(float64) <= float64(now) || claims["iat"].(float64) > float64(now) || claims["auth_time"].(float64) > float64(now) {
		t.Fatal("invalid ID token times")
	}
	accessDigest := sha256.Sum256([]byte(tokens["access_token"].(string)))
	if claims["at_hash"] != base64.RawURLEncoding.EncodeToString(accessDigest[:16]) {
		t.Fatal("access-token hash mismatch")
	}
	for _, claim := range []string{"roles", "email", "name", "credential_version", "password"} {
		if _, ok := claims[claim]; ok {
			t.Fatal("ID token contained unrequested user data")
		}
	}
	return claims
}

func oidcE2ECookie(t *testing.T, response oidcE2EResponse, name, path string, maxAge int) {
	t.Helper()
	var found *http.Cookie
	for _, c := range (&http.Response{Header: response.header}).Cookies() {
		if c.Name == name {
			// Login clears the previous session before issuing its replacement.
			found = c
		}
	}
	if found == nil {
		t.Fatalf("missing %s cookie", name)
	}
	if err := found.Valid(); err != nil {
		t.Fatal(err)
	}
	if found.Path != path || found.Domain != "" || !found.Secure || !found.HttpOnly || found.SameSite != http.SameSiteLaxMode || found.MaxAge != maxAge {
		t.Fatalf("incorrect attributes for %s cookie", name)
	}
	if maxAge < 0 {
		if found.Value != "" || !found.Expires.Before(time.Now()) {
			t.Fatalf("%s cookie was not expired", name)
		}
		return
	}
	if len(found.Value) != 43 || time.Until(found.Expires) < time.Duration(maxAge-5)*time.Second || time.Until(found.Expires) > time.Duration(maxAge)*time.Second {
		t.Fatalf("incorrect credential or lifetime for %s cookie", name)
	}
}

func TestE2EOIDCProviderBrowserConsent(t *testing.T) {
	for _, tc := range []struct {
		name, mount, sessionName, requestName string
		cookies                               *cookie.Config
		refresh                               bool
	}{
		{name: "root", sessionName: "AUTHP_OIDC_SESSION_ID", requestName: "AUTHP_OIDC_REQUEST_ID"},
		{name: "auth mount", mount: "/auth", sessionName: "AUTHP_OIDC_SESSION_ID", requestName: "AUTHP_OIDC_REQUEST_ID"},
		{name: "nested mount", mount: "/tenant/custom", sessionName: "AUTHP_OIDC_SESSION_ID", requestName: "AUTHP_OIDC_REQUEST_ID"},
		{name: "custom prefix with refresh", mount: "/auth", cookies: &cookie.Config{CookieNamePrefix: "PORTAL"}, sessionName: "PORTAL_OIDC_SESSION_ID", requestName: "PORTAL_OIDC_REQUEST_ID", refresh: true},
		{name: "explicit names", mount: "/tenant/custom", cookies: &cookie.Config{CookieNamePrefix: "PORTAL", OIDCSessionIDCookieName: "LOGIN", OIDCRequestIDCookieName: "REQUEST"}, sessionName: "LOGIN", requestName: "REQUEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOIDCE2EFixture(t, tc.mount, tc.refresh, tc.cookies)
			cookiePath := tc.mount
			if cookiePath == "" {
				cookiePath = "/"
			}
			discovery := f.request(t, "GET", "/.well-known/openid-configuration?format=json", nil, nil)
			oidcE2EStatus(t, discovery, 200)
			if len(discovery.header.Values("Set-Cookie")) != 0 {
				t.Fatal("discovery allocated browser state")
			}
			var metadata map[string]any
			if json.Unmarshal(discovery.body, &metadata) != nil {
				t.Fatal("discovery JSON invalid")
			}
			if metadata["issuer"] != f.issuer || metadata["jwks_uri"] != f.issuer+"/oidc/jwks" {
				t.Fatal("incorrect discovery issuer/mount")
			}
			params := f.authorization("basic")
			start := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
			oidcE2EStatus(t, start, 303)
			oidcE2ECookie(t, start, tc.requestName, cookiePath, 600)
			if start.header.Get("Location") != f.issuer+"/login?fresh=1" {
				t.Fatal("authorization did not request login")
			}
			loginPage := f.request(t, "GET", start.header.Get("Location"), nil, nil)
			oidcE2EStatus(t, loginPage, 200)
			completed := f.loginBrowser(t)
			oidcE2ECookie(t, completed, tc.sessionName, cookiePath, 28800)
			if tc.mount != "" {
				for _, path := range []string{"/", "/other", tc.mount + "entication"} {
					target, _ := url.Parse(f.server.URL + path)
					for _, c := range f.client.Jar.Cookies(target) {
						if c.Name == tc.sessionName || c.Name == tc.requestName {
							t.Fatal("provider cookie escaped its portal mount")
						}
					}
				}
			}
			if completed.header.Get("Location") != f.issuer+"/oidc/continue" {
				t.Fatal("login lost OIDC continuation")
			}
			consent := f.request(t, "GET", completed.header.Get("Location"), nil, nil)
			oidcE2EStatus(t, consent, 200)
			re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
			match := re.FindSubmatch(consent.body)
			if len(match) != 2 {
				t.Fatal("consent CSRF missing")
			}
			deniedCSRF := f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {"wrong"}, "decision": {"allow"}}, http.Header{"Origin": {f.server.URL}})
			oidcE2EStatus(t, deniedCSRF, 403)
			approval := f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {html.UnescapeString(string(match[1]))}, "decision": {"allow"}}, http.Header{"Origin": {f.server.URL}})
			oidcE2ECookie(t, approval, tc.requestName, cookiePath, -1)
			code := oidcProviderE2ECode(t, approval)
			tokens := oidcE2ETokens(t, f.exchange(t, "basic", code, oidcE2EVerifier))
			claims := f.verifyIDToken(t, tokens, "basic")
			for _, method := range []string{"GET", "POST"} {
				info := f.request(t, method, "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
				oidcE2EStatus(t, info, 200)
				var userinfo map[string]any
				if json.Unmarshal(info.body, &userinfo) != nil {
					t.Fatal("invalid UserInfo")
				}
				if userinfo["sub"] != claims["sub"] || userinfo["email"] != "alice@example.test" || userinfo["email_verified"] != false {
					t.Fatal("incorrect scoped UserInfo")
				}
			}
			replay := f.exchange(t, "basic", code, oidcE2EVerifier)
			oidcE2EStatus(t, replay, 400)
			revoked := f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
			oidcE2EStatus(t, revoked, 401)
			// Logout must clear both a live session and an unfinished interaction
			// using the same configured names and paths as their issuance.
			params.Set("prompt", "consent")
			pending := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
			oidcE2EStatus(t, pending, 200)
			oidcE2ECookie(t, pending, tc.requestName, cookiePath, 600)
			loggedOut := f.request(t, "GET", "/logout", nil, nil)
			if tc.refresh {
				loggedOut = f.jsonRequest(t, "/api/logout", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}})
				oidcE2EStatus(t, loggedOut, 200)
			}
			oidcE2ECookie(t, loggedOut, tc.sessionName, cookiePath, -1)
			oidcE2ECookie(t, loggedOut, tc.requestName, cookiePath, -1)
			target, _ := url.Parse(f.issuer + "/oidc/continue")
			for _, c := range f.client.Jar.Cookies(target) {
				if c.Name == tc.sessionName || c.Name == tc.requestName {
					t.Fatal("logout left provider credentials in the browser cookie jar")
				}
			}
			params.Set("prompt", "none")
			response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
			target, _ = url.Parse(response.header.Get("Location"))
			if target.Query().Get("error") != "login_required" {
				t.Fatal("logout retained the configured provider session")
			}
		})
	}
}

func TestE2EOIDCClientBindingAndPKCE(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	for _, client := range []string{"second", "post", "public"} {
		t.Run(client, func(t *testing.T) {
			code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization(client).Encode(), nil, nil))
			wrong := f.exchange(t, "basic", code, oidcE2EVerifier)
			oidcE2EStatus(t, wrong, 400)
			missing := f.exchange(t, client, code, "")
			oidcE2EStatus(t, missing, 400)
			bad := f.exchange(t, client, code, strings.Repeat("a", 43))
			oidcE2EStatus(t, bad, 400)
			tokens := oidcE2ETokens(t, f.exchange(t, client, code, oidcE2EVerifier))
			f.verifyIDToken(t, tokens, client)
		})
	}
}

func TestE2EOIDCConcurrentCodeRedemption(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			response := f.exchange(t, "second", code, oidcE2EVerifier)
			if response.status == 200 {
				successes.Add(1)
			} else if response.status != 400 {
				t.Errorf("unexpected concurrent token status %d", response.status)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful redemptions = %d, expected 1", successes.Load())
	}
}

func oidcE2EError(t *testing.T, response oidcE2EResponse, code string) {
	t.Helper()
	var body map[string]any
	if json.Unmarshal(response.body, &body) != nil || body["error"] != code {
		t.Fatalf("expected OAuth error %q at HTTP %d", code, response.status)
	}
}

func TestE2EOIDCProtocolErrors(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	for _, tc := range []struct {
		name    string
		change  func(url.Values)
		status  int
		failure string
	}{
		{"unknown client", func(v url.Values) { v.Set("client_id", "unknown") }, 400, "invalid_request"},
		{"unregistered redirect", func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") }, 400, "invalid_request"},
		{"redirect sibling path", func(v url.Values) { v.Set("redirect_uri", f.callback+"extra") }, 400, "invalid_request"},
		{"redirect case", func(v url.Values) { v.Set("redirect_uri", strings.Replace(f.callback, "rp.", "RP.", 1)) }, 400, "invalid_request"},
		{"duplicate client", func(v url.Values) { v.Add("client_id", "second") }, 400, "invalid_request"},
		{"missing response type", func(v url.Values) { v.Del("response_type") }, 302, "invalid_request"},
		{"implicit type", func(v url.Values) { v.Set("response_type", "id_token") }, 302, "unsupported_response_type"},
		{"missing openid", func(v url.Values) { v.Set("scope", "profile") }, 302, "invalid_scope"},
		{"invalid mode", func(v url.Values) { v.Set("response_mode", "invalid") }, 302, "invalid_request"},
		{"none logged out", func(v url.Values) { v.Set("prompt", "none") }, 302, "login_required"},
		{"none mixed", func(v url.Values) { v.Set("prompt", "none login") }, 302, "invalid_request"},
		{"unknown prompt", func(v url.Values) { v.Set("prompt", "silent") }, 302, "invalid_request"},
		{"negative max age", func(v url.Values) { v.Set("max_age", "-1") }, 302, "invalid_request"},
		{"overflow max age", func(v url.Values) { v.Set("max_age", "9223372036854775808") }, 302, "invalid_request"},
		{"plain PKCE", func(v url.Values) { v.Set("code_challenge_method", "plain") }, 302, "invalid_request"},
		{"bad PKCE", func(v url.Values) { v.Set("code_challenge", "short") }, 302, "invalid_request"},
		{"missing PKCE method", func(v url.Values) { v.Del("code_challenge_method") }, 302, "invalid_request"},
		{"invalid request object", func(v url.Values) { v.Set("request", "invalid") }, 302, "invalid_request_object"},
		{"unsupported request URI", func(v url.Values) { v.Set("request_uri", "https://127.0.0.1/private") }, 302, "request_uri_not_supported"},
		{"unsupported registration", func(v url.Values) { v.Set("registration", "{}") }, 302, "registration_not_supported"},
		{"forged hint", func(v url.Values) { v.Set("id_token_hint", "forged") }, 302, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := f.authorization("second")
			tc.change(params)
			response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
			oidcE2EStatus(t, response, tc.status)
			if tc.status == 400 {
				if response.header.Get("Location") != "" {
					t.Fatal("unsafe error redirect")
				}
				oidcE2EError(t, response, tc.failure)
			} else {
				target, err := url.Parse(response.header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if target.Query().Get("error") != tc.failure || target.Query().Get("state") != params.Get("state") {
					t.Fatal("incorrect authorization error or lost state")
				}
			}
		})
	}
	for _, path := range []string{"/.well-known/openid-configuration", "/oidc/jwks"} {
		response := f.request(t, "HEAD", path, nil, nil)
		oidcE2EStatus(t, response, 200)
		if len(response.body) != 0 {
			t.Fatal("HEAD contained a body")
		}
		response = f.request(t, "POST", path, url.Values{}, nil)
		oidcE2EStatus(t, response, 405)
	}
	for _, path := range []string{"/oidc/token", "/oidc/revoke"} {
		oidcE2EStatus(t, f.request(t, "GET", path, nil, nil), 405)
	}
	oidcE2EStatus(t, f.request(t, "GET", "/oidc/token/", nil, nil), 404)
	oidcE2EStatus(t, f.request(t, "GET", "/oidc/%74oken", nil, nil), 400)
	oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo?access_token=test", nil, nil), 400)
	oidcE2EStatus(t, f.request(t, "GET", "/.well-known/openid-configuration", nil, http.Header{"X-Forwarded-Host": {"evil.test"}}), 400)
	oidcE2EStatus(t, f.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, http.Header{"Origin": {"https://evil.test"}}), 403)
}

func (f *oidcE2EFixture) approve(t *testing.T, response oidcE2EResponse, decision string) oidcE2EResponse {
	t.Helper()
	oidcE2EStatus(t, response, 200)
	re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	match := re.FindSubmatch(response.body)
	if len(match) != 2 {
		t.Fatal("consent form missing")
	}
	return f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {html.UnescapeString(string(match[1]))}, "decision": {decision}}, http.Header{"Origin": {f.server.URL}})
}

func TestE2EOIDCConsentAndPrompt(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	params := f.authorization("basic")
	params.Set("scope", "openid")
	params.Set("prompt", "none")
	response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "consent_required" {
		t.Fatal("silent consent unexpectedly granted")
	}
	params.Del("prompt")
	consent := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	denied := f.approve(t, consent, "deny")
	target, _ = url.Parse(denied.header.Get("Location"))
	if target.Query().Get("error") != "access_denied" {
		t.Fatal("consent denial ignored")
	}
	consent = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	code := oidcProviderE2ECode(t, f.approve(t, consent, "allow"))
	tokens := oidcE2ETokens(t, f.exchange(t, "basic", code, oidcE2EVerifier))
	info := f.request(t, "POST", "/oidc/userinfo", url.Values{"access_token": {tokens["access_token"].(string)}}, nil)
	oidcE2EStatus(t, info, 200)
	var claims map[string]any
	if json.Unmarshal(info.body, &claims) != nil || len(claims) != 1 || claims["sub"] == "" {
		t.Fatal("openid-only UserInfo released profile information")
	}
	params.Set("prompt", "none")
	_ = oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil))
	params.Set("scope", "openid email")
	response = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	target, _ = url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "consent_required" {
		t.Fatal("consent expanded without approval")
	}
	params = f.authorization("second")
	params.Set("prompt", "login")
	response = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	oidcE2EStatus(t, response, 303)
	page := f.request(t, "GET", response.header.Get("Location"), nil, nil)
	oidcE2EStatus(t, page, 200)
	if !strings.Contains(string(page.body), "username") {
		t.Fatal("prompt login reused existing portal authentication")
	}
	bypass := f.request(t, "GET", "/oidc/continue", nil, nil)
	target, _ = url.Parse(bypass.header.Get("Location"))
	if target.Query().Get("error") != "login_required" {
		t.Fatal("fresh-login continuation bypassed")
	}
	f.loginBrowser(t)
	_ = oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/continue", nil, nil))
	params.Del("prompt")
	params.Set("max_age", "0")
	oidcE2EStatus(t, f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil), 303)
}

func TestE2EOIDCOptionalParametersAndFormPost(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	params := f.authorization("second")
	params.Del("nonce")
	params.Set("unknown_future_extension", "ignored")
	params.Set("display", "popup")
	params.Set("ui_locales", "en")
	params.Set("claims_locales", "en")
	params.Set("acr_values", "unknown")
	params.Set("login_hint", "alice")
	code := oidcProviderE2ECode(t, f.request(t, "POST", "/oidc/authorize", params, nil))
	tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
	parts := strings.Split(tokens["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		t.Fatal("invalid ID claims")
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatal("nonce invented when absent")
	}
	params = f.authorization("second")
	params.Set("id_token_hint", tokens["id_token"].(string))
	params.Set("prompt", "none")
	_ = oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil))
	params.Set("client_id", "post")
	response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "invalid_request" {
		t.Fatal("hint audience ignored")
	}
	params = f.authorization("second")
	params.Set("response_mode", "form_post")
	params.Set("state", `<script>alert("x")</script>&state`)
	response = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	oidcE2EStatus(t, response, 200)
	if response.header.Get("Location") != "" || response.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("invalid form-post response headers")
	}
	if strings.Contains(string(response.body), `<script>alert("x")`) {
		t.Fatal("form-post state not escaped")
	}
	if !strings.Contains(string(response.body), "&lt;script&gt;") || !strings.Contains(response.header.Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Fatal("form-post output missing encoding or CSP")
	}
	match := regexp.MustCompile(`name="code" value="([^"]+)"`).FindSubmatch(response.body)
	if len(match) != 2 {
		t.Fatal("form-post code missing")
	}
	oidcE2ETokens(t, f.exchange(t, "second", html.UnescapeString(string(match[1])), oidcE2EVerifier))
}

func oidcE2ERequestObject(t *testing.T, parameters map[string]any) string {
	t.Helper()
	body, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
}

func TestE2EOIDCRequestObjects(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	var idToken string
	for _, mode := range []string{"query", "form_post"} {
		t.Run(mode, func(t *testing.T) {
			inner := map[string]any{}
			for name, values := range f.authorization("second") {
				inner[name] = values[0]
			}
			inner["response_mode"], inner["scope"] = mode, "openid email"
			inner["iss"], inner["aud"] = "second", f.issuer
			inner["max_age"] = 3600
			inner["sub"], inner["roles"], inner["authenticated"] = "administrator", []string{"authp/admin"}, true
			outer := f.authorization("second")
			outer.Set("redirect_uri", "https://unregistered.example.test/callback")
			outer.Set("state", "outer-state")
			outer.Set("nonce", "outer-nonce")
			outer.Set("response_mode", "query")
			outer.Set("request", oidcE2ERequestObject(t, inner))
			response := f.request(t, "GET", "/oidc/authorize?"+outer.Encode(), nil, nil)
			var code string
			if mode == "form_post" {
				oidcE2EStatus(t, response, 200)
				match := regexp.MustCompile(`name="code" value="([^"]+)"`).FindSubmatch(response.body)
				if len(match) != 2 || !strings.Contains(string(response.body), `name="state" value="state &amp; symbols=&#43;"`) {
					t.Fatal("request object form_post response or state missing")
				}
				code = html.UnescapeString(string(match[1]))
			} else {
				code = oidcProviderE2ECode(t, response)
			}
			tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
			claims := f.verifyIDToken(t, tokens, "second")
			idToken = tokens["id_token"].(string)
			info := f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
			oidcE2EStatus(t, info, 200)
			var userinfo map[string]any
			if json.Unmarshal(info.body, &userinfo) != nil || len(userinfo) != 3 || userinfo["sub"] != claims["sub"] || userinfo["email"] != "alice@example.test" || userinfo["sub"] == "administrator" {
				t.Fatal("request object changed identity or released unapproved scope")
			}
		})
	}
	for _, tc := range []struct {
		name, failure string
		inner         map[string]any
		status        int
	}{
		{"invalid inner redirect", "", map[string]any{"redirect_uri": "https://unregistered.example.test/callback"}, 400},
		{"client mismatch", "invalid_request_object", map[string]any{"client_id": "basic"}, 302},
		{"nested request URI", "invalid_request_object", map[string]any{"request_uri": "https://unreachable.example.test"}, 302},
		{"PKCE cannot be removed", "invalid_request", map[string]any{"code_challenge": "", "code_challenge_method": ""}, 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer := f.authorization("public")
			outer.Set("request", oidcE2ERequestObject(t, tc.inner))
			response := f.request(t, "GET", "/oidc/authorize?"+outer.Encode(), nil, nil)
			oidcE2EStatus(t, response, tc.status)
			if tc.status == 400 {
				if response.header.Get("Location") != "" {
					t.Fatal("invalid inner redirect caused navigation")
				}
			} else {
				target, _ := url.Parse(response.header.Get("Location"))
				if target.Query().Get("error") != tc.failure || target.Query().Get("code") != "" {
					t.Fatal("invalid request object authorized a grant")
				}
			}
		})
	}
	outer := f.authorization("second")
	outer.Set("request", idToken)
	response := f.request(t, "GET", "/oidc/authorize?"+outer.Encode(), nil, nil)
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "invalid_request_object" {
		t.Fatal("ID token accepted as request object")
	}
	f.client.Jar = nil
	outer.Set("request", oidcE2ERequestObject(t, map[string]any{"prompt": "none", "sub": "administrator", "authenticated": true}))
	response = f.request(t, "GET", "/oidc/authorize?"+outer.Encode(), nil, nil)
	target, _ = url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "login_required" || target.Query().Get("code") != "" {
		t.Fatal("unsigned request object substituted for actual login")
	}
}

func TestE2EOIDCLogoutAndRevocation(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "access-only", true: "with-refresh"}[refresh], func(t *testing.T) {
			f := newOIDCE2EFixture(t, "/auth", refresh)
			f.loginBrowser(t)
			code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
			tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
			header := http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}}
			oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, header), 200)
			f.request(t, "GET", "/logout", nil, nil)
			if refresh {
				// The confirmation page must retain both sessions until the
				// protected browser POST successfully commits logout.
				oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, header), 200)
				loggedOut := f.jsonRequest(t, "/api/logout", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}})
				oidcE2EStatus(t, loggedOut, 200)
			}
			oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, header), 401)
			params := f.authorization("second")
			params.Set("prompt", "none")
			response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
			target, _ := url.Parse(response.header.Get("Location"))
			if target.Query().Get("error") != "login_required" {
				t.Fatal("logout retained provider session")
			}
		})
	}
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("post").Encode(), nil, nil))
	tokens := oidcE2ETokens(t, f.exchange(t, "post", code, oidcE2EVerifier))
	revoke := url.Values{"client_id": {"post"}, "client_secret": {oidcE2ESecret}, "token": {tokens["access_token"].(string)}}
	oidcE2EStatus(t, f.request(t, "POST", "/oidc/revoke", revoke, nil), 200)
	oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}}), 401)
	revoke.Set("token", "unknown")
	oidcE2EStatus(t, f.request(t, "POST", "/oidc/revoke", revoke, nil), 200)
}

func (f *oidcE2EFixture) jsonRequest(t *testing.T, target string, data any, token string, requestHeaders ...http.Header) oidcE2EResponse {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+target, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, headers := range requestHeaders {
		maps.Copy(r.Header, headers)
	}
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal("JSON request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal("JSON response failed")
	}
	return oidcE2EResponse{status: response.StatusCode, header: response.Header, body: body}
}

func TestE2EOIDCAccountChanges(t *testing.T) {
	for _, operation := range []string{"disable", "reset_password", "delete", "overwrite_auth_challenges", "reload"} {
		t.Run(operation, func(t *testing.T) {
			f := newOIDCE2EFixture(t, "/auth", false)
			// The administrator has a separate browser. Management uses the
			// production authenticated API, never portal/identity internals.
			adminHTTP := *f.client
			adminHTTP.Jar = nil
			admin, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", Username: "admin", Password: tests.TestPwd1}, authclient.Options{HTTPClient: &adminHTTP})
			if err != nil {
				t.Fatal(err)
			}
			adminCredentials, err := admin.Authenticate(t.Context())
			if err != nil {
				t.Fatal("administrator login failed")
			}
			f.loginJSON(t)
			code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
			pending := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
			tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
			if operation == "reload" {
				response := f.jsonRequest(t, "/api/server/reload", map[string]any{"realm": "local"}, adminCredentials.AccessToken)
				oidcE2EStatus(t, response, 200)
			} else {
				response := f.jsonRequest(t, "/api/server/user", map[string]any{"realm": "local", "operation": operation, "user": map[string]any{"username": "alice", "email": "alice@example.test", "challenges": []string{"password", "totp"}}}, adminCredentials.AccessToken)
				oidcE2EStatus(t, response, 200)
				var result map[string]any
				if json.Unmarshal(response.body, &result) != nil || result["status"] != "success" {
					t.Fatal("management operation did not succeed")
				}
			}
			oidcE2EStatus(t, f.exchange(t, "second", pending, oidcE2EVerifier), 400)
			oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}}), 401)
			params := f.authorization("second")
			params.Set("prompt", "none")
			response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
			target, _ := url.Parse(response.header.Get("Location"))
			if target.Query().Get("error") != "login_required" {
				t.Fatal("revoked identity retained silent login")
			}
		})
	}
}

func TestE2EOIDCRequiresCompletedMFA(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	response := f.jsonRequest(t, "/login", map[string]string{"username": "mfauser", "realm": "local"}, "")
	oidcE2EStatus(t, response, 200)
	var auth map[string]any
	if json.Unmarshal(response.body, &auth) != nil {
		t.Fatal("invalid login response")
	}
	checkpoint := map[string]any{"username": "mfauser", "realm": "local", "sandbox_id": auth["sandbox_id"], "sandbox_secret": auth["sandbox_secret"], "challenge_kind": "password", "challenge_response": tests.TestPwd1}
	response = f.jsonRequest(t, "/login", checkpoint, "")
	oidcE2EStatus(t, response, 200)
	if json.Unmarshal(response.body, &auth) != nil || auth["authenticated"] == true {
		t.Fatal("password bypassed MFA")
	}
	params := f.authorization("second")
	params.Set("prompt", "none")
	response = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "login_required" {
		t.Fatal("partial MFA created provider session")
	}
	client, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", Username: "mfauser", Password: tests.TestPwd1, TOTPSecret: "0123456789abcdef0123456789abcdef"}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(t.Context()); err != nil {
		t.Fatal("password plus TOTP login failed")
	}
	code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil))
	tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
	claims := f.verifyIDToken(t, tokens, "second")
	methods, ok := claims["amr"].([]any)
	if !ok || len(methods) != 2 || methods[0] != "pwd" || methods[1] != "otp" {
		t.Fatal("ID token failed to preserve verified MFA methods")
	}
}

func TestE2EOIDCTokenPurposeSeparation(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
	tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
	f.client.Jar = nil
	for _, kind := range []string{"access_token", "id_token"} {
		response := f.request(t, "GET", "/api/server/metadata", nil, http.Header{"Authorization": {"Bearer " + tokens[kind].(string)}})
		oidcE2EStatus(t, response, 401)
	}
	oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["id_token"].(string)}}), 401)
	params := f.authorization("second")
	params.Set("prompt", "none")
	response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, http.Header{"Authorization": {"Bearer " + tokens["id_token"].(string)}})
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "login_required" {
		t.Fatal("bearer ID token substituted for browser login")
	}
}

func TestE2EOIDCBrowserClientCORS(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", false)
	f.loginJSON(t)
	origin := "https://rp.example.test"
	preflight := f.request(t, "OPTIONS", "/oidc/token", nil, http.Header{"Origin": {origin}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"content-type"}})
	oidcE2EStatus(t, preflight, 204)
	if preflight.header.Get("Access-Control-Allow-Origin") != origin || preflight.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("invalid token CORS policy")
	}
	denied := f.request(t, "OPTIONS", "/oidc/token", nil, http.Header{"Origin": {"https://evil.example"}, "Access-Control-Request-Method": {"POST"}})
	oidcE2EStatus(t, denied, 403)
	if denied.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unregistered CORS origin allowed")
	}
	code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("public").Encode(), nil, nil))
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"public"}, "code": {code}, "code_verifier": {oidcE2EVerifier}, "redirect_uri": {f.callback}}
	response := f.request(t, "POST", "/oidc/token", form, http.Header{"Origin": {origin}})
	tokens := oidcE2ETokens(t, response)
	if response.header.Get("Access-Control-Allow-Origin") != origin {
		t.Fatal("public token response not CORS readable")
	}
	info := f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Origin": {origin}, "Authorization": {"Bearer " + tokens["access_token"].(string)}})
	oidcE2EStatus(t, info, 200)
	if info.header.Get("Access-Control-Allow-Origin") != origin {
		t.Fatal("UserInfo not CORS readable")
	}
}

func TestE2EOIDCNativeLoginDoesNotSetBrowserCookies(t *testing.T) {
	f := newOIDCE2EFixture(t, "/auth", true)
	f.client.Jar = nil
	start := f.jsonRequest(t, "/login", map[string]string{"username": "alice", "realm": "local", "refresh_transport": "body"}, "")
	oidcE2EStatus(t, start, 200)
	var auth map[string]any
	if json.Unmarshal(start.body, &auth) != nil {
		t.Fatal("invalid native login")
	}
	response := f.jsonRequest(t, "/login", map[string]any{"username": "alice", "realm": "local", "refresh_transport": "body", "sandbox_id": auth["sandbox_id"], "sandbox_secret": auth["sandbox_secret"], "challenge_kind": "password", "challenge_response": tests.TestPwd1}, "")
	oidcE2EStatus(t, response, 200)
	if len(start.header.Values("Set-Cookie")) != 0 || len(response.header.Values("Set-Cookie")) != 0 {
		t.Fatal("native login created browser cookies")
	}
	var tokens map[string]any
	if json.Unmarshal(response.body, &tokens) != nil || tokens["refresh_token"] == "" || tokens["access_token"] == "" {
		t.Fatal("native refresh credentials missing")
	}
	params := f.authorization("second")
	params.Set("prompt", "none")
	response = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "login_required" {
		t.Fatal("native token substituted for OIDC browser login")
	}
	rotated := f.jsonRequest(t, "/api/refresh_token", map[string]any{"refresh_token": tokens["refresh_token"]}, "")
	oidcE2EStatus(t, rotated, 200)
	if len(rotated.header.Values("Set-Cookie")) != 0 || json.Unmarshal(rotated.body, &tokens) != nil || tokens["refresh_token"] == "" {
		t.Fatal("native refresh changed browser cookies or lost credentials")
	}
	loggedOut := f.jsonRequest(t, "/api/logout", map[string]any{"refresh_token": tokens["refresh_token"]}, "")
	oidcE2EStatus(t, loggedOut, 200)
	if len(loggedOut.header.Values("Set-Cookie")) != 0 {
		t.Fatal("native logout changed browser cookies")
	}
	oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{"refresh_token": tokens["refresh_token"]}, ""), 401)
}
