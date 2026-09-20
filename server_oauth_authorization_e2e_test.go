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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	oauthparser "github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

type directOAuthFixture struct {
	tokenStarted     chan struct{}
	tokenRelease     chan struct{}
	server, upstream *httptest.Server
	runtime          *authcrunch.Server
	config           []byte
	client           *http.Client
	mu               sync.Mutex
	failure          string
	codes            map[string]url.Values
	exchanges        atomic.Int64
	nextCode         atomic.Int64
	gatekeepers      map[string]*authz.Gatekeeper
}

func encodeOAuthStatements(lines ...[]string) []string {
	var statements []string
	for _, line := range lines {
		statements = append(statements, cfgutil.EncodeArgs(line))
	}
	return statements
}

func newDirectOAuthFixture(t *testing.T, settings ...[]string) *directOAuthFixture {
	t.Helper()
	return newDirectOAuthFixtureWithPolicy(t, nil, settings...)
}

func newDirectOAuthFixtureWithPolicy(t *testing.T, configure func(*authz.PolicyConfig), settings ...[]string) *directOAuthFixture {
	t.Helper()
	f := &directOAuthFixture{codes: make(map[string]url.Values), gatekeepers: make(map[string]*authz.Gatekeeper)}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(claims map[string]any) string {
		h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "upstream", "typ": "JWT"})
		p, _ := json.Marshal(claims)
		input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
		return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
	}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.upstream.URL, "authorization_endpoint": f.upstream.URL + "/authorize", "token_endpoint": f.upstream.URL + "/token", "jwks_uri": f.upstream.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "upstream", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(pub)}}})
		case "/authorize":
			q := r.URL.Query()
			if q.Get("client_id") != "direct-client" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("response_type") != "code" || !strings.HasPrefix(q.Get("redirect_uri"), f.server.URL+"/") {
				t.Error("invalid upstream authorization request")
				w.WriteHeader(400)
				return
			}
			code := fmt.Sprintf("code-%d", f.nextCode.Add(1))
			f.codes[code] = q
			http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"state": {q.Get("state")}, "code": {code}}.Encode(), http.StatusFound)
		case "/token":
			f.exchanges.Add(1)
			if f.tokenStarted != nil {
				close(f.tokenStarted)
				select {
				case <-f.tokenRelease:
				case <-r.Context().Done():
					return
				case <-time.After(5 * time.Second):
					t.Error("blocked exchange timed out")
					return
				}
			}
			if r.ParseForm() != nil {
				w.WriteHeader(400)
				return
			}
			q, ok := f.codes[r.Form.Get("code")]
			delete(f.codes, r.Form.Get("code"))
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || r.Form.Get("client_secret") != "synthetic-secret" || r.Form.Get("client_id") != "direct-client" || r.Form.Get("redirect_uri") != q.Get("redirect_uri") || r.Form.Get("state") != q.Get("state") || base64.RawURLEncoding.EncodeToString(challenge[:]) != q.Get("code_challenge") {
				t.Error("invalid bound token exchange")
				w.WriteHeader(400)
				return
			}
			claims := map[string]any{"iss": f.upstream.URL, "aud": "direct-client", "sub": "alice", "email": "alice@example.test", "name": "Alice", "nonce": q.Get("nonce"), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"team/member"}}
			switch f.failure {
			case "nonce":
				claims["nonce"] = "wrong"
			case "issuer":
				claims["iss"] = "https://wrong.test"
			case "audience":
				claims["aud"] = "wrong-client"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "subject":
				claims["sub"] = ""
			case "no roles":
				delete(claims, "roles")
			case "path claims":
				claims["acl"] = map[string]any{"paths": []string{"/private/**"}}
			case "role":
				claims["roles"] = []string{"other"}
			case "malformed":
				claims["name"] = 17
			case "denied":
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
				return
			}
			token := sign(claims)
			if f.failure == "signature" {
				parts := strings.Split(token, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				token = strings.Join(parts, ".")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": token, "access_token": "opaque-upstream-only", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.upstream.Close)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := "primary"
		if strings.HasPrefix(r.URL.Path, "/second") || strings.HasPrefix(r.URL.Path, "/_authcrunch/oauth2/secondary") {
			policy = "secondary"
		}
		g := f.gatekeepers[policy]
		ar := requests.NewAuthorizationRequest()
		if err := g.Authenticate(w, r, ar); err != nil {
			if ar.Response.Authorized || ar.Response.Bypassed {
				t.Error("failed authorization granted access")
			}
			return
		}
		if !ar.Response.Authorized && !ar.Response.Bypassed {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"uri": r.URL.RequestURI(), "method": r.Method, "subject": r.Header.Get("X-Token-Subject"), "email": r.Header.Get("X-User-Email"), "roles": r.Header.Get("X-Token-User-Roles"), "cookie": r.Header.Get("Cookie"), "identity": ar.Response.User, "bypassed": ar.Response.Bypassed})
	}))
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("company", encodeOAuthStatements([]string{"realm", "company"}, []string{"driver", "generic"}, []string{"client_id", "direct-client"}, []string{"client_secret", "synthetic-secret"}, []string{"base_auth_url", f.upstream.URL}, []string{"metadata_url", f.upstream.URL + "/.well-known/openid-configuration"}, []string{"tls", "verification", "disabled"}))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &authcrunch.Config{IdentityProviders: []*idp.IdentityProviderConfig{provider}}
	for _, name := range []string{"primary", "secondary"} {
		lines := [][]string{{"use", "oauth", "identity", "provider", "company"}}
		if name == "primary" {
			for _, line := range settings {
				resolved := append([]string(nil), line...)
				for i, value := range resolved {
					if value == "fixture-origin" {
						resolved[i] = f.server.URL
					}
				}
				lines = append(lines, resolved)
			}
		}
		oc, err := oauthparser.NewOAuthAuthorizationConfigFromDirectives(name, encodeOAuthStatements(lines...))
		if err != nil {
			t.Fatal(err)
		}
		policy := &authz.PolicyConfig{Name: name, PassClaimsWithHeaders: true, StripTokenEnabled: true, ValidateMethodPath: true, HeaderInjectionConfigs: []*injector.Config{{Header: "X-User-Email", Field: "email"}}, AccessListRules: []*acl.RuleConfiguration{
			{Conditions: []string{"prefix match path /admin"}, Action: "deny stop"},
			{Conditions: []string{"match roles team/member"}, Action: "allow stop"},
		}, BypassConfigs: []*bypass.Config{{MatchType: "exact", URI: "/public"}}}
		if name == "primary" && configure != nil {
			configure(policy)
		}
		if err := policy.ConfigureOAuth(oc); err != nil {
			t.Fatal(err)
		}
		cfg.AuthorizationPolicies = append(cfg.AuthorizationPolicies, policy)
	}
	f.config, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored authcrunch.Config
	if err = json.Unmarshal(f.config, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.AuthenticationPortals) != 0 || len(restored.IdentityStores) != 0 {
		t.Fatal("fixture must have no portal or identity store")
	}
	f.runtime, err = authcrunch.NewServer(&restored, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, name := range []string{"primary", "secondary"} {
		f.gatekeepers[name], err = f.runtime.GetGatekeeperByName(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	pool.AddCert(f.upstream.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(transport.CloseIdleConnections)
	f.client = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f.client.Jar, _ = cookiejar.New(nil)
	return f
}

type directOAuthResponse struct {
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

func (f *directOAuthFixture) request(t *testing.T, client *http.Client, method, location string, headers http.Header) directOAuthResponse {
	t.Helper()
	if strings.HasPrefix(location, "/") {
		location = f.server.URL + location
	}
	req, err := http.NewRequestWithContext(t.Context(), method, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, values := range headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("direct OAuth HTTP request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return directOAuthResponse{resp.StatusCode, resp.Header, body, resp.Cookies()}
}

func directOAuthStatus(t *testing.T, r directOAuthResponse, want int) {
	t.Helper()
	if r.status != want {
		t.Fatalf("HTTP status %d, want %d", r.status, want)
	}
}
func (f *directOAuthFixture) callback(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	start := f.request(t, client, "GET", target, nil)
	directOAuthStatus(t, start, 302)
	if start.header.Get("Cache-Control") != "no-store" {
		t.Fatal("login response cacheable")
	}
	authorized := f.request(t, client, "GET", start.header.Get("Location"), nil)
	directOAuthStatus(t, authorized, 302)
	return authorized.header.Get("Location")
}

func TestE2EServerDirectOAuthAuthorization(t *testing.T) {
	f := newDirectOAuthFixture(t)
	target := "/private/report%20name?q=one%2Btwo&redirect_url=https%3A%2F%2Fevil.test&state=application-state&code=application-code"
	callback := f.callback(t, f.client, target)
	completed := f.request(t, f.client, "GET", callback, nil)
	directOAuthStatus(t, completed, 303)
	if completed.header.Get("Location") != target {
		t.Fatal("original URI not preserved")
	}
	var session *http.Cookie
	for _, c := range completed.cookies {
		if c.Name == "AUTHZ_primary_SESSION" {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.Domain != "" || session.MaxAge != 900 || strings.Contains(session.Value, ".") {
		t.Fatal("session cookie security or lifetime incorrect")
	}
	for range 2 {
		response := f.request(t, f.client, "GET", target, http.Header{"X-Token-Subject": {"spoofed"}, "X-User-Email": {"spoofed"}})
		directOAuthStatus(t, response, 200)
		var downstream map[string]any
		if err := json.Unmarshal(response.body, &downstream); err != nil {
			t.Fatal(err)
		}
		if downstream["subject"] != "alice" || downstream["email"] != "alice@example.test" || downstream["uri"] != target || strings.Contains(downstream["cookie"].(string), session.Value) || !strings.Contains(downstream["roles"].(string), "authp/user") {
			t.Fatal("wrong downstream identity or credential stripping")
		}
	}
	directOAuthStatus(t, f.request(t, f.client, "GET", "/admin/secret", nil), 403)
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 400)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/second/resource", nil), 302)
	public := f.request(t, f.client, "GET", "/public", http.Header{"X-Token-Subject": {"spoof"}, "X-User-Email": {"spoof"}})
	directOAuthStatus(t, public, 200)
	var downstream map[string]any
	_ = json.Unmarshal(public.body, &downstream)
	if downstream["subject"] != "" || downstream["email"] != "" {
		t.Fatal("bypass retained spoofed identity")
	}
	directOAuthStatus(t, f.request(t, f.client, "GET", "/_authcrunch/oauth2/primary/logout", nil), 405)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/_authcrunch/oauth2/primary/logout", http.Header{"Origin": {"https://evil.test"}}), 403)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/_authcrunch/oauth2/primary/logout", http.Header{"Origin": {f.server.URL}}), 204)
	stolen := *f.client
	stolen.Jar = nil
	directOAuthStatus(t, f.request(t, &stolen, "GET", "/private", http.Header{"Cookie": {session.Name + "=" + session.Value}}), 302)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 401)
	if f.exchanges.Load() != 1 {
		t.Fatal("session requests or callback replay exchanged additional codes")
	}
}

func TestE2EServerDirectOAuthRejections(t *testing.T) {
	f := newDirectOAuthFixture(t)
	for _, mode := range []string{"nonce", "issuer", "audience", "expired", "subject", "signature", "malformed", "denied", "role"} {
		t.Run(mode, func(t *testing.T) {
			f.mu.Lock()
			f.failure = mode
			f.mu.Unlock()
			client := *f.client
			client.Jar, _ = cookiejar.New(nil)
			callback := f.callback(t, &client, "/private")
			result := f.request(t, &client, "GET", callback, nil)
			want := 401
			if mode == "role" {
				want = 403
			}
			directOAuthStatus(t, result, want)
			for _, c := range result.cookies {
				if c.Name == "AUTHZ_primary_SESSION" && c.MaxAge > 0 {
					t.Fatal("rejected identity issued a session")
				}
			}
			directOAuthStatus(t, f.request(t, &client, "GET", callback, nil), 400)
		})
	}
}

func TestE2EServerDirectOAuthBrowserBinding(t *testing.T) {
	f := newDirectOAuthFixture(t)
	callback := f.callback(t, f.client, "/private")
	other := *f.client
	other.Jar, _ = cookiejar.New(nil)
	directOAuthStatus(t, f.request(t, &other, "GET", callback, nil), 400)
	u, _ := url.Parse(callback)
	q := u.Query()
	q.Add("state", q.Get("state"))
	u.RawQuery = q.Encode()
	directOAuthStatus(t, f.request(t, f.client, "GET", u.String(), nil), 400)
	u, _ = url.Parse(callback)
	q = u.Query()
	q.Set("state", "wrong")
	u.RawQuery = q.Encode()
	directOAuthStatus(t, f.request(t, f.client, "GET", u.String(), nil), 400)
	if f.exchanges.Load() != 0 {
		t.Fatal("invalid callback reached token endpoint")
	}
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 400)
	// The session cookie is not an upstream bearer credential or query token.
	noJar := *f.client
	noJar.Jar = nil
	origin, _ := url.Parse(f.server.URL)
	var secret string
	for _, c := range f.client.Jar.Cookies(origin) {
		if c.Name == "AUTHZ_primary_SESSION" {
			secret = c.Value
		}
	}
	directOAuthStatus(t, f.request(t, &noJar, "POST", "/private", http.Header{"Authorization": {"Bearer " + secret}}), 401)
	directOAuthStatus(t, f.request(t, &noJar, "POST", "/private?access_token="+url.QueryEscape(secret), nil), 401)
	// An encoded callback cannot become an endpoint alias or reach the backend.
	directOAuthStatus(t, f.request(t, f.client, "GET", "/_authcrunch/oauth2/primary/%61uthorization-code-callback", nil), 400)
	for _, target := range []string{"//evil.test/private", "/%2f%2fevil.test/private", "/%5cevil.test/private"} {
		directOAuthStatus(t, f.request(t, &other, "GET", target, nil), 400)
	}
}

func TestE2EServerDirectOAuthConfiguredLimits(t *testing.T) {
	f := newDirectOAuthFixtureWithPolicy(t, func(p *authz.PolicyConfig) {
		p.AccessListRules = []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}
	}, []string{"oauth", "public", "origin", "fixture-origin"}, []string{"oauth", "base", "path", "/custom/login"}, []string{"oauth", "session", "cookie", "name", "__Host-custom_session"}, []string{"oauth", "login", "cookie", "name", "__Secure-custom_login"}, []string{"oauth", "session", "lifetime", "1"}, []string{"oauth", "maximum", "sessions", "1"}, []string{"oauth", "maximum", "pending", "logins", "1"})
	f.mu.Lock()
	f.failure = "no roles"
	f.mu.Unlock()
	other := *f.client
	other.Jar, _ = cookiejar.New(nil)
	callback := f.callback(t, f.client, "/private")
	if !strings.HasPrefix(callback, f.server.URL+"/custom/login/authorization-code-callback?") {
		t.Fatal("callback override lost")
	}
	directOAuthStatus(t, f.request(t, &other, "GET", "/private", nil), 503)
	result := f.request(t, f.client, "GET", callback, nil)
	directOAuthStatus(t, result, 303)
	var session *http.Cookie
	for _, c := range result.cookies {
		if c.Name == "__Host-custom_session" {
			session = c
		}
	}
	if session == nil || session.MaxAge != 1 {
		t.Fatal("session customization lost")
	}
	allowed := f.request(t, f.client, "GET", "/private", nil)
	directOAuthStatus(t, allowed, 200)
	var body map[string]any
	_ = json.Unmarshal(allowed.body, &body)
	if body["roles"] != "authp/user" {
		t.Fatal("role-free upstream identity did not get only baseline role")
	}
	callback = f.callback(t, &other, "/private")
	directOAuthStatus(t, f.request(t, &other, "GET", callback, nil), 503)
	time.Sleep(1100 * time.Millisecond)
	expired := *f.client
	expired.Jar = nil
	directOAuthStatus(t, f.request(t, &expired, "POST", "/private", http.Header{"Cookie": {session.Name + "=" + session.Value}}), 401)
	// Expired sessions release admission capacity; a new login can complete.
	callback = f.callback(t, &other, "/private")
	directOAuthStatus(t, f.request(t, &other, "GET", callback, nil), 303)
	directOAuthStatus(t, f.request(t, &other, "POST", "/custom/login/logout", http.Header{"Origin": {f.server.URL}}), 204)
}

func TestE2EServerDirectOAuthConcurrentCallback(t *testing.T) {
	f := newDirectOAuthFixture(t)
	callback := f.callback(t, f.client, "/private")
	origin, _ := url.Parse(f.server.URL)
	var cookies []string
	for _, c := range f.client.Jar.Cookies(origin) {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	client := *f.client
	client.Jar = nil
	const attempts = 8
	statuses := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			response := f.request(t, &client, "GET", callback, http.Header{"Cookie": {strings.Join(cookies, "; ")}})
			statuses <- response.status
		})
	}
	wg.Wait()
	close(statuses)
	successes, failures := 0, 0
	for status := range statuses {
		switch status {
		case 303:
			successes++
		case 400:
			failures++
		default:
			t.Errorf("unexpected concurrent callback status %d", status)
		}
	}
	if successes != 1 || failures != attempts-1 || f.exchanges.Load() != 1 {
		t.Fatal("callback not redeemed exactly once")
	}
}

func TestE2EServerDirectOAuthLifecycle(t *testing.T) {
	f := newDirectOAuthFixture(t)
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	pending := *f.client
	pending.Jar, _ = cookiejar.New(nil)
	unfinished := f.callback(t, &pending, "/private")
	if err := f.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 503)
	directOAuthStatus(t, f.request(t, &pending, "GET", unfinished, nil), 503)
	var config authcrunch.Config
	if err := json.Unmarshal(f.config, &config); err != nil {
		t.Fatal(err)
	}
	replacement, err := authcrunch.NewServer(&config, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := replacement.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, name := range []string{"primary", "secondary"} {
		f.gatekeepers[name], err = replacement.GetGatekeeperByName(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	directOAuthStatus(t, f.request(t, &pending, "GET", unfinished, nil), 400)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 401)
	callback = f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
}

func TestE2EServerDirectOAuthEndpointAndRequestPolicies(t *testing.T) {
	f := newDirectOAuthFixtureWithPolicy(t, func(p *authz.PolicyConfig) {
		p.BypassConfigs = append(p.BypassConfigs, &bypass.Config{MatchType: "prefix", URI: "/_authcrunch/"})
		p.AccessListRules = append([]*acl.RuleConfiguration{{Conditions: []string{"match method HEAD"}, Action: "deny stop"}}, p.AccessListRules...)
	})
	directOAuthStatus(t, f.request(t, f.client, "GET", "/_authcrunch/oauth2/primary/authorization-code-callback", nil), 400)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/_authcrunch/oauth2/primary/authorization-code-callback", nil), 405)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/_authcrunch/oauth2/primary/unknown", nil), 404)
	start := f.request(t, f.client, "HEAD", "/private", nil)
	directOAuthStatus(t, start, 302)
	authorize := f.request(t, f.client, "GET", start.header.Get("Location"), nil)
	directOAuthStatus(t, authorize, 302)
	directOAuthStatus(t, f.request(t, f.client, "GET", authorize.header.Get("Location"), nil), 403)
	// GET target denial happens before session issuance too.
	callback := f.callback(t, f.client, "/admin/secret")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 403)
	callback = f.callback(t, f.client, "/private")
	u, _ := url.Parse(callback)
	q := u.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	u.RawQuery = q.Encode()
	directOAuthStatus(t, f.request(t, f.client, "GET", u.String(), nil), 401)
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 400)
	// Host headers cannot retarget a pinned origin or a pending callback.
	request, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-Host", "evil.test")
	request.Header.Set("X-Forwarded-Proto", "http")
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(location.Query().Get("redirect_uri"), f.server.URL+"/") {
		t.Fatal("forwarded headers selected callback")
	}
}

func TestE2EServerDirectOAuthLogoutCancelsExchange(t *testing.T) {
	f := newDirectOAuthFixture(t)
	callback := f.callback(t, f.client, "/private")
	started, release := make(chan struct{}), make(chan struct{})
	f.mu.Lock()
	f.tokenStarted = started
	f.tokenRelease = release
	f.mu.Unlock()
	done := make(chan directOAuthResponse, 1)
	go func() { done <- f.request(t, f.client, "GET", callback, nil) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("token exchange not reached")
	}
	directOAuthStatus(t, f.request(t, f.client, "POST", "/_authcrunch/oauth2/primary/logout", http.Header{"Origin": {f.server.URL}}), 204)
	close(release)
	select {
	case response := <-done:
		directOAuthStatus(t, response, 401)
		for _, c := range response.cookies {
			if c.Name == "AUTHZ_primary_SESSION" && c.MaxAge > 0 {
				t.Fatal("logout allowed in-flight session issuance")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exchange did not finish")
	}
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 401)
}
