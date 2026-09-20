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

package authz

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

type oauthProviderStub struct {
	idp.IdentityProvider
	kind         string
	config       map[string]any
	unconfigured bool
	closed       bool
	reply        func(*requests.Request) error
}

func TestE2EOAuthPersistentRestoreIsAtomic(t *testing.T) {
	g := newOAuthUnitGatekeeper(t, &oauthProviderStub{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := requests.NewAuthorizationRequest()
		if err := g.Authenticate(w, r, ar); err != nil {
			t.Errorf("authenticate: %v", err)
			return
		}
		if ar.Response.Authorized {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	record, err := storage.OpenRecord("oauth-sessions/policy", "binding")
	if err != nil {
		t.Fatal(err)
	}
	usr, err := g.oauth.identity(map[string]any{"sub": "alice"}, oauthUnitRequest("GET", "https://app.test/", nil), "https://app.test")
	if err != nil {
		t.Fatal(err)
	}
	data, err := usr.MarshalSession()
	if err != nil {
		t.Fatal(err)
	}
	credential := oauthCredential()
	entries := []oauthSessionState{
		{Hash: sha256.Sum256([]byte(credential)), Origin: server.URL, User: data, Expires: time.Now().Add(time.Hour)},
		{Hash: sha256.Sum256([]byte("invalid")), Origin: server.URL, User: []byte("invalid"), Expires: time.Now().Add(time.Hour)},
	}
	if err = record.Encode(entries); err != nil {
		t.Fatal(err)
	}
	if err = g.ConfigurePersistentState(storage, "binding"); err == nil {
		t.Fatal("invalid persistent state accepted")
	}
	if len(g.oauth.sessions) != 0 || g.oauth.state != nil || g.oauth.stateStore != nil {
		t.Fatal("failed restore published partial OAuth authority")
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: g.oauth.config.SessionCookieName, Value: credential})
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("failed restore authorized a partially restored OAuth session")
	}
	if err = record.Encode(entries[:1]); err != nil {
		t.Fatal(err)
	}
	if err = g.ConfigurePersistentState(storage, "binding"); err != nil {
		t.Fatalf("gatekeeper was not retryable after atomic restore failure: %v", err)
	}
	response, err = server.Client().Do(request.Clone(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("healthy restored OAuth session was not authorized")
	}
}

func TestE2EOAuthPersistentCapacityRefusalPreservesAuthority(t *testing.T) {
	p := &oauthProviderStub{}
	g := newOAuthUnitGatekeeper(t, p)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := requests.NewAuthorizationRequest()
		if err := g.Authenticate(w, r, ar); err != nil {
			t.Errorf("authenticate: %v", err)
			return
		}
		if ar.Response.Authorized {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 60 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	directory := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	record, err := storage.OpenRecord("oauth-sessions/policy", "binding")
	if err != nil {
		t.Fatal(err)
	}
	userData := func(size int) []byte {
		usr, userErr := g.oauth.identity(map[string]any{"sub": "alice", "name": strings.Repeat("x", size)}, oauthUnitRequest("GET", server.URL+"/", nil), server.URL)
		if userErr != nil {
			t.Fatal(userErr)
		}
		data, marshalErr := usr.MarshalSession()
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return data
	}
	oldCredential := oauthCredential()
	now := time.Now()
	entries := []oauthSessionState{{Hash: sha256.Sum256([]byte(oldCredential)), Origin: server.URL, User: userData(0), Expires: now.Add(time.Hour)}}
	full := userData(512 << 10)
	low, high := 0, min(200, g.oauth.config.MaxSessions-len(entries))
	for low < high {
		mid := low + (high-low+1)/2
		candidate := slices.Clone(entries)
		for i := range mid {
			candidate = append(candidate, oauthSessionState{Hash: sha256.Sum256(fmt.Appendf(nil, "filler-%d", i)), Origin: server.URL, User: full, Expires: now.Add(time.Hour)})
		}
		if _, prepareErr := record.PrepareEncode(candidate); errors.Is(prepareErr, state.ErrCapacity) {
			high = mid - 1
		} else if prepareErr != nil {
			t.Fatal(prepareErr)
		} else {
			low = mid
		}
	}
	for i := range low {
		entries = append(entries, oauthSessionState{Hash: sha256.Sum256(fmt.Appendf(nil, "filler-%d", i)), Origin: server.URL, User: full, Expires: now.Add(time.Hour)})
	}
	if err = record.Encode(entries); err != nil {
		t.Fatal(err)
	}
	if err = g.ConfigurePersistentState(storage, "binding"); err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, cookies ...*http.Cookie) *http.Response {
		t.Helper()
		req, reqErr := http.NewRequestWithContext(t.Context(), method, server.URL+path, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		response, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		response.Body.Close()
		return response
	}
	oldCookie := &http.Cookie{Name: g.oauth.config.SessionCookieName, Value: oldCredential}
	if response := request(http.MethodPost, "/private", oldCookie); response.StatusCode != http.StatusNoContent {
		t.Fatal("existing OAuth session was not restored")
	}
	p.reply = func(r *requests.Request) error {
		if r.Upstream.Request.URL.Path != g.oauth.config.CallbackPath() {
			r.Response.Code = http.StatusFound
			r.Response.RedirectURL = "https://provider.test/authorize?state=provider-state"
			return nil
		}
		r.Response.Code = http.StatusOK
		r.Response.Payload = map[string]any{"sub": "replacement", "name": strings.Repeat("x", 512<<10)}
		return nil
	}
	begin := request(http.MethodGet, "/replacement")
	var loginCookie *http.Cookie
	for _, cookie := range begin.Cookies() {
		if cookie.Name == g.oauth.config.LoginCookieName && cookie.MaxAge > 0 {
			loginCookie = cookie
		}
	}
	if begin.StatusCode != http.StatusFound || loginCookie == nil {
		t.Fatal("replacement OAuth login did not begin")
	}
	callback := request(http.MethodGet, g.oauth.config.CallbackPath()+"?state=provider-state&code=synthetic", loginCookie, oldCookie)
	positiveSession := false
	for _, cookie := range callback.Cookies() {
		positiveSession = positiveSession || (cookie.Name == g.oauth.config.SessionCookieName && cookie.MaxAge > 0)
	}
	if callback.StatusCode != http.StatusServiceUnavailable || positiveSession || storage.Err() != nil {
		t.Fatal("OAuth capacity refusal published replacement authority or poisoned storage")
	}
	if response := request(http.MethodPost, "/private", oldCookie); response.StatusCode != http.StatusNoContent {
		t.Fatal("OAuth capacity refusal revoked the previous session")
	}
	unrelated, err := storage.OpenRecord("unrelated", "binding")
	if err != nil {
		t.Fatal(err)
	}
	if err = unrelated.Encode(map[string]string{"healthy": "yes"}); err != nil {
		t.Fatal("OAuth capacity refusal poisoned unrelated state", err)
	}
	logoutRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+g.oauth.config.LogoutPath(), nil)
	if err != nil {
		t.Fatal(err)
	}
	logoutRequest.Header.Set("Origin", server.URL)
	logoutRequest.AddCookie(oldCookie)
	logoutResponse, err := client.Do(logoutRequest)
	if err != nil {
		t.Fatal(err)
	}
	logoutResponse.Body.Close()
	if logoutResponse.StatusCode != http.StatusNoContent {
		t.Fatal("OAuth logout failed after capacity refusal")
	}
	g.Close()
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	g = newOAuthUnitGatekeeper(t, p)
	if err = g.ConfigurePersistentState(storage, "binding"); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPost, "/private", oldCookie); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("OAuth logout was not durable after capacity refusal")
	}
}

func (p *oauthProviderStub) GetName() string  { return "provider" }
func (p *oauthProviderStub) GetRealm() string { return "realm" }
func (p *oauthProviderStub) GetKind() string {
	if p.kind != "" {
		return p.kind
	}
	return "oauth"
}
func (p *oauthProviderStub) Configured() bool          { return !p.unconfigured }
func (p *oauthProviderStub) GetConfig() map[string]any { return p.config }
func (p *oauthProviderStub) Close()                    { p.closed = true }
func (p *oauthProviderStub) Request(_ operator.Type, r *requests.Request) error {
	if p.reply != nil {
		return p.reply(r)
	}
	r.Response.Code = 302
	r.Response.RedirectURL = "https://provider.test/authorize?state=provider-state"
	return nil
}
func (p *oauthProviderStub) CancelLogin(string, [32]byte, string) bool { return true }

type oauthProviderWithoutCancellation struct{ idp.IdentityProvider }

func newOAuthUnitGatekeeper(t *testing.T, p *oauthProviderStub) *Gatekeeper {
	t.Helper()
	g, err := NewGatekeeperWithIdentityProviders(&PolicyConfig{Name: "policy", OAuth: &OAuthAuthorizationConfig{IdentityProvider: "provider"}, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}, []idp.IdentityProvider{p}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return g
}

func TestOAuthAuthorizationProviderSelection(t *testing.T) {
	cfg := &OAuthAuthorizationConfig{IdentityProvider: "provider"}
	if err := cfg.Validate("policy"); err != nil {
		t.Fatal(err)
	}
	for _, providers := range [][]idp.IdentityProvider{
		nil, {&oauthProviderStub{kind: "saml"}}, {&oauthProviderStub{unconfigured: true}}, {&oauthProviderStub{}, &oauthProviderStub{}},
		{&oauthProviderWithoutCancellation{IdentityProvider: &oauthProviderStub{}}},
		{&oauthProviderStub{config: map[string]any{"js_callback_enabled": true}}},
		{&oauthProviderStub{config: map[string]any{"response_type": []any{"token"}}}},
		{&oauthProviderStub{config: map[string]any{"response_type": []string{"code", "token"}}}},
		{&oauthProviderStub{config: map[string]any{"response_type": "code"}}},
	} {
		if _, err := newOAuthAuthorization(cfg, providers); err == nil {
			t.Fatal("unsupported provider configuration accepted")
		}
	}
	p := &oauthProviderStub{config: map[string]any{"response_type": []string{"code"}}}
	g := newOAuthUnitGatekeeper(t, p)
	g.Close()
	g.Close()
	if p.closed {
		t.Fatal("gatekeeper closed a shared provider")
	}
	if _, err := NewGatekeeper(g.config, zap.NewNop()); err == nil {
		t.Fatal("OAuth gatekeeper without provider accepted")
	}
}

func TestOAuthAuthorizationPendingLifetimeAndFailures(t *testing.T) {
	p := &oauthProviderStub{}
	g := newOAuthUnitGatekeeper(t, p)
	r := oauthUnitRequest("GET", "https://app.test/private", nil)
	w := httptest.NewRecorder()
	if err := g.Authenticate(w, r, requests.NewAuthorizationRequest()); err != nil || w.Code != 302 {
		t.Fatal("login failed")
	}
	var browser *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == g.oauth.config.LoginCookieName {
			browser = c
		}
	}
	if browser == nil {
		t.Fatal("no browser binding")
	}
	key := sha256.Sum256([]byte(browser.Value))
	g.oauth.mu.Lock()
	login := g.oauth.logins[key]
	login.expires = time.Now().Add(-time.Second)
	g.oauth.logins[key] = login
	g.oauth.mu.Unlock()
	callback := oauthUnitRequest("GET", "https://app.test"+g.oauth.config.CallbackPath()+"?state=provider-state&code=unused", nil)
	callback.AddCookie(browser)
	w = httptest.NewRecorder()
	_ = g.Authenticate(w, callback, requests.NewAuthorizationRequest())
	if w.Code != 400 {
		t.Fatal("expired login was accepted")
	}
	for _, mode := range []string{"error", "empty", "http", "missing state"} {
		t.Run(mode, func(t *testing.T) {
			p.reply = func(rr *requests.Request) error {
				if mode == "error" {
					return fmt.Errorf("synthetic upstream failure")
				}
				rr.Response.Code = 302
				switch mode {
				case "empty":
					rr.Response.RedirectURL = ""
				case "http":
					rr.Response.RedirectURL = "http://provider.test?state=x"
				case "missing state":
					rr.Response.RedirectURL = "https://provider.test"
				}
				return nil
			}
			response := httptest.NewRecorder()
			_ = g.Authenticate(response, r, requests.NewAuthorizationRequest())
			if response.Code != 502 || len(response.Result().Cookies()) != 0 {
				t.Fatal("invalid provider redirect was emitted")
			}
			if len(g.oauth.logins) != 0 {
				t.Fatal("failed login retained admission capacity")
			}
		})
	}
}

func TestOAuthAuthorizationOriginAndCookies(t *testing.T) {
	o := &oauthAuthorization{}
	for _, tc := range []struct {
		target, host, configured string
		valid                    bool
	}{
		{"https://app.test/private", "app.test", "", true},
		{"http://app.test/private", "app.test", "", false},
		{"http://app.test/private", "app.test", "https://app.test", true},
		{"https://evil.test/private", "evil.test", "https://app.test", false},
		{"https://app.test/private", "app.test/evil", "", false},
		{"https://app.test/private", "user@app.test", "", false},
		{"https://app.test/private", "app.test#evil", "", false},
		{"https://app.test/private", "app.test?evil", "", false},
		{"https://app.test/private", "app.test\\evil", "", false},
	} {
		r := oauthUnitRequest("GET", tc.target, nil)
		r.Host = tc.host
		o.config.PublicOrigin = tc.configured
		r.Header.Set("X-Forwarded-Host", "ignored.test")
		r.Header.Set("X-Forwarded-Proto", "https")
		_, valid := o.origin(r)
		if valid != tc.valid {
			t.Errorf("origin valid=%v want %v", valid, tc.valid)
		}
	}
	for _, value := range []string{"short", strings.Repeat("a", 44), strings.Repeat("x", 43)} {
		r := oauthUnitRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: value})
		if _, ok := oauthCookie(r, "session"); ok {
			t.Fatal("malformed credential accepted")
		}
	}
	r := oauthUnitRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: oauthCredential()})
	r.AddCookie(&http.Cookie{Name: "session", Value: oauthCredential()})
	if _, ok := oauthCookie(r, "session"); ok {
		t.Fatal("duplicate credentials accepted")
	}
}

func TestOAuthAuthorizationCallbackGrammar(t *testing.T) {
	g := newOAuthUnitGatekeeper(t, &oauthProviderStub{})
	for _, query := range []string{"", "state=x", "state=x&code=a&code=b", "state=x&code=a&error=no", "state=x&code=", "state=x&code=a&access_token=token", "state=x&code=a&id_token=token", "state=x;code=a", "state=x&code=%zz", "state=x&code=a&iss=", "state=x&code=" + strings.Repeat("a", 16385)} {
		r := oauthUnitRequest("GET", "https://app.test"+g.oauth.config.CallbackPath(), nil)
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		_ = g.Authenticate(w, r, requests.NewAuthorizationRequest())
		if w.Code != 400 {
			t.Fatal("malformed callback accepted")
		}
	}
}

func TestOAuthAuthorizationClosedAndExpiredSession(t *testing.T) {
	g := newOAuthUnitGatekeeper(t, &oauthProviderStub{})
	r := oauthUnitRequest("GET", "https://app.test/private", nil)
	usr, err := g.oauth.identity(map[string]any{"sub": "alice", "roles": []any{"team/member"}}, r, "https://app.test")
	if err != nil {
		t.Fatal(err)
	}
	secret := oauthCredential()
	key := sha256.Sum256([]byte(secret))
	g.oauth.sessions[key] = oauthSession{origin: "https://app.test", user: usr, expires: time.Now().Add(-time.Second)}
	r.AddCookie(&http.Cookie{Name: g.oauth.config.SessionCookieName, Value: secret})
	w := httptest.NewRecorder()
	_ = g.Authenticate(w, r, requests.NewAuthorizationRequest())
	if w.Code != 302 {
		t.Fatal("expired session remained authorized")
	}
	if _, exists := g.oauth.sessions[key]; exists {
		t.Fatal("expired session not reclaimed")
	}
	g.Close()
	if len(g.oauth.logins) != 0 || len(g.oauth.sessions) != 0 {
		t.Fatal("closed state retained credentials")
	}
	w = httptest.NewRecorder()
	_ = g.Authenticate(w, r, requests.NewAuthorizationRequest())
	if w.Code != 503 {
		t.Fatal("closed gatekeeper accepted request")
	}
}

func TestOAuthAuthorizationIdentityIsolation(t *testing.T) {
	g := newOAuthUnitGatekeeper(t, &oauthProviderStub{})
	for _, roles := range []any{nil, "team/member", []string{"team/member"}, []any{"team/member"}} {
		claims := map[string]any{"sub": "alice"}
		if roles != nil {
			claims["roles"] = roles
		}
		usr, err := g.oauth.identity(claims, oauthUnitRequest("GET", "https://app.test/", nil), "https://app.test")
		if err != nil || !usr.HasRole("authp/user") {
			t.Fatal("verified identity missing baseline role")
		}
		if usr.HasRole("guest", "anonymous") {
			t.Fatal("verified identity acquired fallback roles")
		}
		if _, exists := claims["iss"]; exists {
			t.Fatal("provider payload mutated")
		}
	}
	for _, claims := range []any{nil, "not claims", map[string]any{"sub": ""}, map[string]any{"sub": " ", "roles": []string{"admin"}}, map[string]any{"sub": 7}, map[string]any{"sub": "alice", "roles": 7}} {
		if _, err := g.oauth.identity(claims, &http.Request{URL: &url.URL{}}, "https://app.test"); err == nil {
			t.Fatal("malformed identity accepted")
		}
	}
}

// Match the origin-form URL a real net/http server supplies, while retaining
// httptest's TLS and Host metadata for HTTPS input.
func oauthUnitRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.URL.Scheme, r.URL.Host = "", ""
	r.RequestURI = r.URL.RequestURI()
	return r
}
