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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
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
