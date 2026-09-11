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
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

const refreshTestOrigin = "https://auth.example.test"
const refreshTestSecret = "0123456789abcdef0123456789abcdef"

type refreshPortalFixture struct {
	portal *Portal
	store  *local.IdentityStore
}

func newRefreshPortal(t *testing.T, enabled, mfa bool) *refreshPortalFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	req := &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1, Password: tests.TestPwd1, Roles: []string{"authp/user", "original"}}}
	if err := db.AddUser(req); err != nil {
		t.Fatal(err)
	}
	if mfa {
		req.MfaToken = requests.MfaToken{Type: "totp", Comment: "test factor", Secret: refreshTestSecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
		if err := db.AddMfaToken(req); err != nil {
			t.Fatal(err)
		}
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "localdb", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	cfg := &PortalConfig{Name: "refresh-test", IdentityStores: []string{"localdb"}, CookieConfig: cookie.NewConfig(), API: &APIConfig{ProfileEnabled: true}}
	if enabled {
		cfg.RefreshTokens = &RefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: refreshTestOrigin, BasePath: "/auth", BodyTransportEnabled: true}
	}
	p, err := NewPortal(PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return &refreshPortalFixture{p, store.(*local.IdentityStore)}
}
func (f *refreshPortalFixture) request(t *testing.T, method, path, body string, browser bool, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, refreshTestOrigin+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if browser {
		r.Header.Set("Origin", refreshTestOrigin)
		r.Header.Set(refreshRequestHeader, "1")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	if err := f.portal.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	return w
}
func decodeAuth(t *testing.T, w *httptest.ResponseRecorder) *apiauth.AuthResponse {
	t.Helper()
	a := &apiauth.AuthResponse{}
	if w.Code != 200 {
		t.Fatalf("unexpected HTTP status %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), a); err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *refreshPortalFixture) begin(t *testing.T, transport string) *apiauth.AuthResponse {
	t.Helper()
	b, _ := json.Marshal(apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", RefreshTransport: transport})
	return decodeAuth(t, f.request(t, "POST", "/auth/login", string(b), transport == "cookie"))
}
func (f *refreshPortalFixture) challenge(t *testing.T, a *apiauth.AuthResponse, transport, kind, value string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", RefreshTransport: transport, SandboxID: a.SandboxID, SandboxSecret: a.SandboxSecret, ChallengeKind: kind, ChallengeResponse: value})
	return f.request(t, "POST", "/auth/login", string(b), transport == "cookie")
}
func (f *refreshPortalFixture) login(t *testing.T, transport string) *httptest.ResponseRecorder {
	t.Helper()
	return f.challenge(t, f.begin(t, transport), transport, "password", tests.TestPwd1)
}
func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	t.Fatalf("missing cookie %s", name)
	return nil
}
func tokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func testTOTP() string {
	mac := hmac.New(sha1.New, []byte(refreshTestSecret))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().Unix()/30))
	mac.Write(b[:])
	s := mac.Sum(nil)
	off := s[len(s)-1] & 15
	value := binary.BigEndian.Uint32(s[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func TestPortalRefreshBrowserAndExpiredAccess(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	login := f.login(t, "cookie")
	meta := decodeAuth(t, login)
	if !meta.Authenticated || meta.AccessToken != "" || meta.RefreshToken != "" || meta.SessionID == "" {
		t.Fatal("browser response exposed tokens or omitted metadata")
	}
	oldRefresh := responseCookie(t, login, p.config.RefreshTokens.CookieName)
	access := responseCookie(t, login, p.cookie.AccessTokenCookieName)
	if !oldRefresh.Secure || !oldRefresh.HttpOnly || oldRefresh.SameSite != http.SameSiteLaxMode || oldRefresh.Domain != "" || oldRefresh.Path != "/auth" || oldRefresh.MaxAge <= access.MaxAge {
		t.Fatal("incorrect independent refresh cookie policy")
	}
	claims := tokenClaims(t, access.Value)
	if claims["sid"] != meta.SessionID || claims["auth_time"] == nil {
		t.Fatal("missing authentication context")
	}
	expired, err := user.NewUser(map[string]any{"sub": tests.TestUser1, "roles": []string{"authp/user"}, "exp": time.Now().Unix() - 1, "iat": time.Now().Unix() - 100, "nbf": time.Now().Unix() - 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.keystore.SignToken(nil, nil, expired); err != nil {
		t.Fatal(err)
	}
	stale := &http.Cookie{Name: p.cookie.AccessTokenCookieName, Value: expired.Token}
	refreshed := f.request(t, "POST", "/auth/api/refresh_token", "{}", true, oldRefresh, stale)
	nextMeta := decodeAuth(t, refreshed)
	next := responseCookie(t, refreshed, p.config.RefreshTokens.CookieName)
	if next.Value == oldRefresh.Value || nextMeta.SessionID != meta.SessionID {
		t.Fatal("rotation failed")
	}
	newAccess := responseCookie(t, refreshed, p.cookie.AccessTokenCookieName)
	newClaims := tokenClaims(t, newAccess.Value)
	if newClaims["auth_time"] != claims["auth_time"] || newClaims["jti"] == claims["jti"] {
		t.Fatal("authentication event changed or jti reused")
	}
	// Verify the actual KMS output through the ordinary access authorization path.
	who := f.request(t, "GET", "/auth/whoami", "", true, newAccess)
	if who.Code != 200 {
		t.Fatalf("refreshed access JWT rejected: %d", who.Code)
	}
	system := f.request(t, "POST", "/auth/api/system", "{}", true, stale)
	if system.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary API accepted expired access: %d", system.Code)
	}
	if w := f.request(t, "POST", "/auth/api/refresh_token", "{}", true, oldRefresh); w.Code != 401 {
		t.Fatal("spent credential accepted")
	}
	if w := f.request(t, "POST", "/auth/api/refresh_token", "{}", true, next); w.Code != 401 {
		t.Fatal("descendant survived replay")
	}
}

func TestPortalRefreshNativeAndLogout(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	first := decodeAuth(t, f.login(t, "body"))
	if first.AccessToken == "" || first.RefreshToken == "" {
		t.Fatal("native tokens missing")
	}
	body, _ := json.Marshal(map[string]string{"refresh_token": first.RefreshToken})
	next := decodeAuth(t, f.request(t, "POST", "/auth/api/refresh_token", string(body), false))
	if next.RefreshToken == first.RefreshToken {
		t.Fatal("native token did not rotate")
	}
	body, _ = json.Marshal(map[string]string{"refresh_token": next.RefreshToken})
	logout := f.request(t, "POST", "/auth/api/logout", string(body), false)
	if logout.Code != 200 {
		t.Fatal("logout failed")
	}
	if w := f.request(t, "POST", "/auth/api/refresh_token", string(body), false); w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}

func TestPortalRefreshRequestValidation(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	login := f.login(t, "cookie")
	decodeAuth(t, login)
	credential := responseCookie(t, login, p.config.RefreshTokens.CookieName)
	cases := []struct {
		name   string
		status int
		edit   func(*http.Request)
	}{
		{"get", 405, func(r *http.Request) { r.Method = "GET" }},
		{"missing origin", 403, func(r *http.Request) { r.Header.Del("Origin") }},
		{"wrong origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{"null origin", 403, func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"duplicate origin", 403, func(r *http.Request) { r.Header.Add("Origin", refreshTestOrigin) }},
		{"missing csrf header", 403, func(r *http.Request) { r.Header.Del(refreshRequestHeader) }},
		{"cross site", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"navigation", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "navigate") }},
		{"wrong host", 403, func(r *http.Request) { r.Host = "evil.example" }},
		{"cleartext", 403, func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"query", 400, func(r *http.Request) { r.URL.RawQuery = "refresh_token=abc" }},
		{"wrong mount", 404, func(r *http.Request) { r.URL.Path = "/other/api/refresh_token" }},
		{"encoded path", 404, func(r *http.Request) { r.URL.RawPath = "/auth/api/%72efresh_token" }},
		{"content type", 415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"duplicate cookie", 400, func(r *http.Request) { r.AddCookie(credential) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", refreshTestOrigin+"/auth/api/refresh_token", strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Origin", refreshTestOrigin)
			r.Header.Set(refreshRequestHeader, "1")
			r.AddCookie(credential)
			tc.edit(r)
			w := httptest.NewRecorder()
			if err := p.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status {
				t.Fatalf("got %d, want %d", w.Code, tc.status)
			}
		})
	}
	for _, body := range []string{"null", "[]", "{} {}", `{"unknown":true}`, `{"refresh_token":false}`, `{"refresh_token":null}`, `{"refresh_token":"a","refresh_token":"b"}`, `{"refresh_token":"a","refresh_\u0074oken":"b"}`, strings.Repeat(" ", 1025) + "{}"} {
		t.Run("malformed body", func(t *testing.T) {
			w := f.request(t, "POST", "/auth/api/refresh_token", body, true, credential)
			if w.Code != 400 {
				t.Fatalf("malformed body got %d", w.Code)
			}
		})
	}
	mixed, _ := json.Marshal(map[string]string{"refresh_token": credential.Value})
	if w := f.request(t, "POST", "/auth/api/refresh_token", string(mixed), true, credential); w.Code != 400 {
		t.Fatal("mixed credentials accepted")
	}
	// Rejected requests must leave the legitimate token usable.
	decodeAuth(t, f.request(t, "POST", "/auth/api/refresh_token", "{}", true, credential))
}

func TestPortalRefreshCurrentIdentity(t *testing.T) {
	for _, tc := range []string{"roles", "password", "disable", "delete", "challenge", "reload", "revoke all"} {
		t.Run(tc, func(t *testing.T) {
			f := newRefreshPortal(t, true, false)
			first := decodeAuth(t, f.login(t, "body"))
			var err error
			switch tc {
			case "roles":
				_, err = f.store.OverwriteUserRoles(tests.TestUser1, tests.TestEmail1, []string{"authp/user", "updated"})
			case "password":
				_, err = f.store.ResetUserPassword(tests.TestUser1, tests.TestEmail1)
			case "disable":
				err = f.store.DisableUser(tests.TestUser1, tests.TestEmail1)
			case "delete":
				err = f.store.DeleteUser(tests.TestUser1, tests.TestEmail1)
			case "challenge":
				_, err = f.store.OverwriteUserAuthChallengeRules(tests.TestUser1, tests.TestEmail1, []string{"password", "totp"})
			case "reload":
				err = f.store.Reload()
			case "revoke all":
				r := &requests.Request{User: requests.User{Username: tests.TestUser1}}
				if err = f.store.Request(operator.IdentifyUser, r); err == nil {
					err = f.store.RevokeUserSessions(context.Background(), r.Authentication.UserID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(map[string]string{"refresh_token": first.RefreshToken})
			w := f.request(t, "POST", "/auth/api/refresh_token", string(b), false)
			if tc == "roles" {
				next := decodeAuth(t, w)
				claims := tokenClaims(t, next.AccessToken)
				roles := fmt.Sprint(claims["roles"])
				if strings.Contains(roles, "original") || !strings.Contains(roles, "updated") {
					t.Fatal("stale authorization")
				}
			} else if w.Code != 401 {
				t.Fatalf("security change accepted: %d", w.Code)
			}
		})
	}
}

func TestPortalRefreshMFAAndProofRace(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprint(reset), func(t *testing.T) {
			f := newRefreshPortal(t, true, true)
			start := f.begin(t, "body")
			password := decodeAuth(t, f.challenge(t, start, "body", "password", tests.TestPwd1))
			if password.Authenticated || password.RefreshToken != "" || password.NextChallenge != "totp" {
				t.Fatal("credentials issued before MFA")
			}
			if reset {
				if _, err := f.store.ResetUserPassword(tests.TestUser1, tests.TestEmail1); err != nil {
					t.Fatal(err)
				}
			}
			w := f.challenge(t, password, "body", "totp", testTOTP())
			if reset {
				if w.Code != 401 {
					t.Fatalf("pre-reset proof issued token: %d", w.Code)
				}
				return
			}
			result := decodeAuth(t, w)
			claims := tokenClaims(t, result.AccessToken)
			if fmt.Sprint(claims["amr"]) != "[pwd otp]" {
				t.Fatal("incorrect authentication methods")
			}
			b, _ := json.Marshal(map[string]string{"refresh_token": result.RefreshToken})
			decodeAuth(t, f.request(t, "POST", "/auth/api/refresh_token", string(b), false))
		})
	}
}

func TestPortalRefreshSingleUseLogin(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	start := f.begin(t, "body")
	payload, _ := json.Marshal(apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", RefreshTransport: "body", SandboxID: start.SandboxID, SandboxSecret: start.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1})
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", refreshTestOrigin+"/auth/login", strings.NewReader(string(payload)))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			_ = f.portal.ServeHTTP(context.Background(), w, r, requests.NewRequest())
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("one proof issued %d sessions", success)
	}
}

func TestPortalRefreshDisabledAndBrowserLogout(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	if f.portal.refresh != nil {
		t.Fatal("disabled portal allocated refresh manager")
	}
	accessOnly := decodeAuth(t, f.login(t, "cookie"))
	if accessOnly.AccessToken == "" || accessOnly.RefreshToken != "" {
		t.Fatal("disabled behavior changed")
	}
	if w := f.request(t, "POST", "/auth/api/refresh_token", "{}", true); w.Code != 404 {
		t.Fatal("disabled endpoint available")
	}
	f = newRefreshPortal(t, true, false)
	login := f.login(t, "cookie")
	decodeAuth(t, login)
	credential := responseCookie(t, login, f.portal.config.RefreshTokens.CookieName)
	r := httptest.NewRequest("GET", refreshTestOrigin+"/auth/logout", nil)
	r.AddCookie(credential)
	w := httptest.NewRecorder()
	if err := f.portal.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), "session-logout") {
		t.Fatal("GET logout did not require protected POST")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == credential.Name && c.MaxAge < 0 {
			t.Fatal("GET cleared refresh without revocation")
		}
	}
	logout := f.request(t, "POST", "/auth/api/logout", "{}", true, credential)
	if logout.Code != 200 {
		t.Fatal("browser logout failed")
	}
	deleted := false
	for _, c := range logout.Result().Cookies() {
		if c.Name == credential.Name {
			deleted = c.Path == "/auth" && c.Domain == "" && c.MaxAge < 0 && c.Secure && c.HttpOnly
		}
	}
	if !deleted {
		t.Fatal("refresh cookie deletion mismatches issuance")
	}
	if w := f.request(t, "POST", "/auth/api/refresh_token", "{}", true, credential); w.Code != 401 {
		t.Fatal("copied credential survived logout")
	}
}

func TestPortalRefreshBrowserFormLogin(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	request := func(method, path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, refreshTestOrigin+path, strings.NewReader(form.Encode()))
		if method == "POST" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", refreshTestOrigin)
		}
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		if err := p.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
			t.Fatal(err)
		}
		return w
	}
	start := request("POST", "/auth/login", url.Values{"username": {tests.TestUser1}, "realm": {"local"}}, nil)
	if start.Code != 303 {
		t.Fatalf("form login failed: %d", start.Code)
	}
	sandbox := responseCookie(t, start, p.cookie.SandboxIDCookieName)
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	password := request("POST", location.Path, url.Values{"secret": {tests.TestPwd1}}, sandbox)
	if password.Code != 303 {
		t.Fatalf("password checkpoint failed: %d", password.Code)
	}
	completed := request("GET", location.Path, nil, sandbox)
	if completed.Code != 303 {
		t.Fatalf("completed form failed: %d", completed.Code)
	}
	responseCookie(t, completed, p.config.RefreshTokens.CookieName)
	if retry := request("GET", location.Path, nil, sandbox); retry.Code == 303 {
		t.Fatal("completed sandbox issued again")
	}
}

func TestPortalRefreshTransformerChallenge(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	first := decodeAuth(t, f.login(t, "body"))
	tr, err := transformer.NewFactory([]*transformer.Config{{Matchers: []string{"match realm local"}, Actions: []string{"require mfa"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.portal.transformer = tr
	b, _ := json.Marshal(map[string]string{"refresh_token": first.RefreshToken})
	if w := f.request(t, "POST", "/auth/api/refresh_token", string(b), false); w.Code != 401 {
		t.Fatalf("new MFA requirement bypassed: %d", w.Code)
	}
}

func TestPortalNewLoginReplacesRefreshFamily(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	first := f.login(t, "cookie")
	decodeAuth(t, first)
	old := responseCookie(t, first, f.portal.config.RefreshTokens.CookieName)
	start := f.begin(t, "cookie")
	body, _ := json.Marshal(apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", SandboxID: start.SandboxID, SandboxSecret: start.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1})
	second := f.request(t, "POST", "/auth/login", string(body), true, old)
	decodeAuth(t, second)
	next := responseCookie(t, second, f.portal.config.RefreshTokens.CookieName)
	if w := f.request(t, "POST", "/auth/api/refresh_token", "{}", true, old); w.Code != 401 {
		t.Fatal("previous login family survived replacement")
	}
	decodeAuth(t, f.request(t, "POST", "/auth/api/refresh_token", "{}", true, next))
}

func TestPortalRefreshContinuationAndFreshLogin(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	login := f.login(t, "cookie")
	decodeAuth(t, login)
	credential := responseCookie(t, login, f.portal.config.RefreshTokens.CookieName)
	for _, endpoint := range []string{"/auth/portal", "/auth/login", "/auth/login?fresh=1"} {
		t.Run(endpoint, func(t *testing.T) {
			r := httptest.NewRequest("GET", refreshTestOrigin+endpoint, nil)
			r.AddCookie(credential)
			w := httptest.NewRecorder()
			if err := f.portal.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("continuation returned %d", w.Code)
			}
			continuation := strings.Contains(w.Body.String(), `data-action="continue"`)
			if continuation == strings.Contains(endpoint, "fresh=1") {
				t.Fatal("fresh login did not escape the continuation flow")
			}
		})
	}
}

func FuzzRefreshRequestBody(f *testing.F) {
	for _, body := range []string{"{}", `{"refresh_token":"token"}`, `{"refresh_token":"a","refresh_token":"b"}`, "null"} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest("POST", refreshTestOrigin+"/auth/api/refresh_token", strings.NewReader(body))
		token, present, err := parseRefreshBody(httptest.NewRecorder(), r)
		if err == nil && present != (token != "") {
			t.Fatal("ambiguous parsed credential")
		}
	})
}
