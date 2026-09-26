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

package oauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newDirectAuthorizationProvider(t *testing.T) *oauth.IdentityProvider {
	t.Helper()
	provider, err := oauth.NewIdentityProvider(&oauth.Config{
		Name: "shared", Realm: "shared", Driver: "github",
		ClientID: "client", ClientSecret: "secret",
		BaseAuthURL: "https://identity.example/", AuthorizationURL: "https://identity.example/authorize", TokenURL: "https://identity.example/token",
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	return provider
}

func newDirectAuthorizationGatekeeper(t *testing.T, provider *oauth.IdentityProvider, name string) *authz.Gatekeeper {
	t.Helper()
	gate, err := authz.NewGatekeeperWithIdentityProviders(&authz.PolicyConfig{
		Name:            name,
		OAuth:           &authz.OAuthAuthorizationConfig{IdentityProvider: "shared"},
		AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
	}, []idp.IdentityProvider{provider}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	return gate
}

type directAuthorizationFixture struct {
	server *httptest.Server
	client *http.Client
	gates  map[string]*authz.Gatekeeper
}

func newDirectAuthorizationFixture(t *testing.T) *directAuthorizationFixture {
	t.Helper()
	f := &directAuthorizationFixture{gates: make(map[string]*authz.Gatekeeper)}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := "primary"
		if r.URL.Path == "/secondary" || strings.HasPrefix(r.URL.Path, "/_authcrunch/oauth2/secondary") {
			name = "secondary"
		}
		gate := f.gates[name]
		if gate == nil {
			http.Error(w, "missing policy", http.StatusServiceUnavailable)
			return
		}
		if err := gate.Authenticate(w, r, requests.NewAuthorizationRequest()); err != nil {
			http.Error(w, "authorization failed", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(f.server.Close)
	f.client = f.server.Client()
	f.client.Timeout = 10 * time.Second
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f.client.Jar, _ = cookiejar.New(nil)
	return f
}

func (f *directAuthorizationFixture) request(t *testing.T, method, target string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", f.server.URL)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode
}

func TestE2EDirectAuthorizationReleasesProviderState(t *testing.T) {
	provider := newDirectAuthorizationProvider(t)
	provider.SetStateCapacityForTesting(1)
	gate := newDirectAuthorizationGatekeeper(t, provider, "primary")
	fixture := newDirectAuthorizationFixture(t)
	fixture.gates["primary"] = gate

	for i := range 4 {
		status := fixture.request(t, http.MethodGet, "/private")
		if status != http.StatusFound {
			t.Fatalf("replacement %d returned HTTP %d", i, status)
		}
		if got := provider.StateCountForTesting(); got != 1 {
			t.Fatalf("replacement %d retained %d provider states", i, got)
		}
	}

	logout := fixture.request(t, http.MethodPost, "/_authcrunch/oauth2/primary/logout")
	if logout != http.StatusNoContent || provider.StateCountForTesting() != 0 {
		t.Fatalf("logout returned HTTP %d with %d provider states", logout, provider.StateCountForTesting())
	}

	status := fixture.request(t, http.MethodGet, "/private")
	if status != http.StatusFound || provider.StateCountForTesting() != 1 {
		t.Fatal("login before close did not occupy provider state")
	}
	gate.Close()
	if provider.StateCountForTesting() != 0 {
		t.Fatal("gatekeeper close retained provider state")
	}
}

func TestE2EDirectAuthorizationCancellationIsPolicyScoped(t *testing.T) {
	provider := newDirectAuthorizationProvider(t)
	provider.SetStateCapacityForTesting(2)
	primary := newDirectAuthorizationGatekeeper(t, provider, "primary")
	secondary := newDirectAuthorizationGatekeeper(t, provider, "secondary")
	fixture := newDirectAuthorizationFixture(t)
	fixture.gates["primary"], fixture.gates["secondary"] = primary, secondary

	primaryStatus := fixture.request(t, http.MethodGet, "/primary")
	secondaryStatus := fixture.request(t, http.MethodGet, "/secondary")
	if primaryStatus != http.StatusFound || secondaryStatus != http.StatusFound || provider.StateCountForTesting() != 2 {
		t.Fatalf("shared provider did not retain both policy transactions: primary=%d secondary=%d states=%d", primaryStatus, secondaryStatus, provider.StateCountForTesting())
	}
	primary.Close()
	if got := provider.StateCountForTesting(); got != 1 {
		t.Fatalf("provider state count after closing one policy = %d, want 1", got)
	}
	logout := fixture.request(t, http.MethodPost, "/_authcrunch/oauth2/secondary/logout")
	if logout != http.StatusNoContent || provider.StateCountForTesting() != 0 {
		t.Fatal("surviving policy could not cancel its own transaction")
	}
}

func TestE2EDirectAuthorizationLinkedIn(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_LINKEDIN_E2E_CHILD") == "1" {
		runE2EDirectAuthorizationLinkedInChild(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2EDirectAuthorizationLinkedIn$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_LINKEDIN_E2E_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("LinkedIn direct authorization child failed: %v\n%s", err, output)
	}
}

func runE2EDirectAuthorizationLinkedInChild(t *testing.T) {
	var authorizeCalls, tokenCalls, linkedInCalls atomic.Int64
	var failure atomic.Value
	failure.Store("")
	var upstream *httptest.Server
	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "api.linkedin.com" && r.URL.Path == "/v2/userinfo":
			linkedInCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer linkedin-access" {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			switch failure.Load().(string) {
			case "userinfo status":
				http.Error(w, "denied", http.StatusUnauthorized)
			case "userinfo oversized":
				_ = json.NewEncoder(w).Encode(map[string]any{"sub": "linkedin-user", "padding": strings.Repeat("x", (1<<20)+1)})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"sub": "linkedin-user", "email": "alice@example.test", "name": "Alice"})
			}
		case r.URL.Path == "/metadata":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": upstream.URL, "authorization_endpoint": upstream.URL + "/authorize",
				"token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys",
				"userinfo_endpoint": upstream.URL + "/userinfo",
			})
		case r.URL.Path == "/authorize":
			authorizeCalls.Add(1)
			q := r.URL.Query()
			if q.Get("state") == "" || q.Get("redirect_uri") == "" || q.Has("nonce") || q.Has("code_challenge") {
				http.Error(w, "wrong LinkedIn authorization parameters", http.StatusBadRequest)
				return
			}
			callback, err := url.Parse(q.Get("redirect_uri"))
			if err != nil {
				http.Error(w, "invalid callback", http.StatusBadRequest)
				return
			}
			values := callback.Query()
			values.Set("state", q.Get("state"))
			values.Set("code", "linkedin-code")
			callback.RawQuery = values.Encode()
			http.Redirect(w, r, callback.String(), http.StatusFound)
		case r.URL.Path == "/token":
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil || r.Form.Get("code") != "linkedin-code" || r.Form.Get("state") == "" || r.Form.Get("redirect_uri") == "" || r.Form.Has("code_verifier") {
				http.Error(w, "wrong LinkedIn token parameters", http.StatusBadRequest)
				return
			}
			accessToken := any("linkedin-access")
			if failure.Load().(string) == "token type" {
				accessToken = 7
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken, "id_token": "compatibility-token", "token_type": "Bearer"})
		case r.URL.Path == "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "linkedin-user", "email": "alice@example.test", "name": "Alice"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	proxy := newNamedDriverConnectProxy(t, upstream.Listener.Addr().String())
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	provider, err := oauth.NewIdentityProvider(&oauth.Config{
		Name: "linkedin", Realm: "linkedin", Driver: "linkedin",
		ClientID: "linkedin-client", ClientSecret: "linkedin-secret",
		BaseAuthURL: upstream.URL + "/", MetadataURL: upstream.URL + "/metadata",
		KeyVerificationDisabled: true, TLSInsecureSkipVerify: true,
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}
	gate, err := authz.NewGatekeeperWithIdentityProviders(&authz.PolicyConfig{
		Name: "linkedin", OAuth: &authz.OAuthAuthorizationConfig{IdentityProvider: "linkedin"},
		AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
	}, []idp.IdentityProvider{provider}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	fixture := newDirectAuthorizationFixture(t)
	fixture.gates["primary"] = gate

	providerURL := fixture.requestLocation(t, "/private")
	callbackURL := fixture.requestLocation(t, providerURL)
	returnURI := fixture.requestLocation(t, callbackURL)
	if returnURI != "/private" {
		t.Fatalf("callback redirect = %q, want /private", returnURI)
	}
	if status := fixture.request(t, http.MethodGet, "/private"); status != http.StatusOK {
		t.Fatalf("authenticated LinkedIn request returned HTTP %d", status)
	}
	if authorizeCalls.Load() != 1 || tokenCalls.Load() != 1 || linkedInCalls.Load() != 1 {
		t.Fatalf("LinkedIn calls authorize=%d token=%d userinfo=%d, want 1 each", authorizeCalls.Load(), tokenCalls.Load(), linkedInCalls.Load())
	}

	for _, mode := range []string{"token type", "userinfo status", "userinfo oversized"} {
		failure.Store(mode)
		gate, err := authz.NewGatekeeperWithIdentityProviders(&authz.PolicyConfig{
			Name:            "linkedin_" + strings.ReplaceAll(mode, " ", "_"),
			OAuth:           &authz.OAuthAuthorizationConfig{IdentityProvider: "linkedin"},
			AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
		}, []idp.IdentityProvider{provider}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		failedFixture := newDirectAuthorizationFixture(t)
		failedFixture.gates["primary"] = gate
		providerURL := failedFixture.requestLocation(t, "/private")
		callbackURL := failedFixture.requestLocation(t, providerURL)
		status, cookies := failedFixture.requestStatus(t, callbackURL)
		if status != http.StatusUnauthorized {
			t.Fatalf("LinkedIn %s callback returned HTTP %d", mode, status)
		}
		for _, cookie := range cookies {
			if strings.HasSuffix(cookie.Name, "_SESSION") && cookie.MaxAge > 0 {
				t.Fatalf("LinkedIn %s issued a session", mode)
			}
		}
		gate.Close()
	}
}

func (f *directAuthorizationFixture) requestLocation(t *testing.T, target string) string {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.server.URL + target
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("request %s returned HTTP %d", target, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func (f *directAuthorizationFixture) requestStatus(t *testing.T, target string) (int, []*http.Cookie) {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.server.URL + target
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Cookies()
}

func newNamedDriverConnectProxy(t *testing.T, target string) *httptest.Server {
	t.Helper()
	allowed := map[string]bool{
		"api.linkedin.com:443":             true,
		"api.github.com:443":               true,
		"cloudidentity.googleapis.com:443": true,
		"discord.com:443":                  true,
		"graph.facebook.com:443":           true,
	}
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for connection := range connections {
			_ = connection.Close()
		}
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || !allowed[r.Host] {
			http.Error(w, "proxy target rejected", http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			http.Error(w, "proxy upstream unavailable", http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		deadline := time.Now().Add(15 * time.Second)
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
		mu.Lock()
		connections[client], connections[upstream] = struct{}{}, struct{}{}
		mu.Unlock()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(upstream, client)
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(client, upstream)
				done <- struct{}{}
			}()
			<-done
			_ = client.Close()
			_ = upstream.Close()
			<-done
			mu.Lock()
			delete(connections, client)
			delete(connections, upstream)
			mu.Unlock()
		}()
	}))
}
