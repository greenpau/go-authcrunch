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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// A child process isolates ProxyFromEnvironment's cache. All OAuth endpoints,
// including the driver's fixed GitHub URLs, terminate at a local TLS fixture.
func TestE2EOAuthGithubTransforms(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_GITHUB_TRANSFORM_CHILD") == "1" {
		runE2EOAuthGithubTransforms(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2EOAuthGithubTransforms$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_GITHUB_TRANSFORM_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GitHub transform journey failed: %v\n%s", err, output)
	}
	t.Logf("GitHub transform journeys:\n%s", output)
}

type githubTransformCase struct {
	name, id, login, driver, realm, matcher, orgFilter, orgBody string
	additionalMatcher                                           string
	wantID                                                      string
	wantOrgs                                                    []string
	allow, reject                                               bool
	orgStatus                                                   int
}

func runE2EOAuthGithubTransforms(t *testing.T) {
	var mu sync.Mutex
	var scenario githubTransformCase
	var callback, state string
	var exchanges, profiles, organizations int
	var upstream *httptest.Server
	upstream = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/metadata":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": upstream.URL, "authorization_endpoint": upstream.URL + "/authorize",
				"token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys",
			})
		case "/login/oauth/authorize", "/authorize":
			q := r.URL.Query()
			if q.Get("client_id") != oidcE2EClientID || q.Get("redirect_uri") != callback || q.Get("state") == "" {
				http.Error(w, "invalid authorization", http.StatusBadRequest)
				return
			}
			state = q.Get("state")
			redirect, _ := url.Parse(callback)
			values := redirect.Query()
			values.Set("state", state)
			values.Set("code", "synthetic-code")
			redirect.RawQuery = values.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		case "/login/oauth/access_token", "/token":
			if err := r.ParseForm(); err != nil || state == "" || r.Form.Get("state") != state ||
				r.Form.Get("client_id") != oidcE2EClientID || r.Form.Get("client_secret") != oidcE2EClientSecret ||
				r.Form.Get("redirect_uri") != callback || r.Form.Get("code") != "synthetic-code" {
				http.Error(w, "invalid exchange", http.StatusBadRequest)
				return
			}
			state = ""
			exchanges++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "token_type": "Bearer", "id_token": "compatibility-token"})
		case "/user", "/v2/userinfo":
			profiles++
			prefix := "token "
			if scenario.driver == "linkedin" {
				prefix = "Bearer "
			}
			if r.Header.Get("Authorization") != prefix+"synthetic-access" {
				http.Error(w, "unauthenticated", 401)
				return
			}
			profile := map[string]any{
				"login": scenario.login, "sub": "linkedin-user", "name": "Alice", "email": "alice@example.test",
				"organizations_url": "https://api.github.com/users/" + scenario.login + "/orgs",
				// These untrusted extra fields must never override fetched evidence.
				"github_id": "123", "github_orgs": []string{"acme"}, "origin": "github",
			}
			if scenario.id != "" {
				profile["id"] = json.RawMessage(scenario.id)
			}
			_ = json.NewEncoder(w).Encode(profile)
		case "/user/emails":
			_, _ = io.WriteString(w, `[{"email":"alice@example.test","primary":true,"verified":true}]`)
		default:
			if strings.HasPrefix(r.URL.Path, "/users/") && strings.HasSuffix(r.URL.Path, "/orgs") {
				organizations++
				if r.Header.Get("Authorization") != "token synthetic-access" {
					http.Error(w, "unauthenticated", 401)
					return
				}
				if scenario.orgStatus != 0 {
					w.WriteHeader(scenario.orgStatus)
				}
				_, _ = io.WriteString(w, scenario.orgBody)
				return
			}
			http.NotFound(w, r)
		}
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{githubFixtureCertificate(t)}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	proxy := newGithubTransformProxy(t, upstream.Listener.Addr().String())
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")
	cases := []githubTransformCase{
		{name: "exact", id: "123", matcher: "match github id exact 123", wantID: "123", allow: true},
		{name: "renamed account", login: "renamed-alice", id: "123", matcher: "match github id exact 123", wantID: "123", allow: true},
		{name: "exact miss", id: "124", matcher: "match github id exact 123", wantID: "124"},
		{name: "regex", id: "456", matcher: "match github id regex ^(123|456)$", wantID: "456", allow: true},
		{name: "regex miss", id: "1234", matcher: "match github id regex ^123$", wantID: "1234"},
		{name: "large integer", id: "9007199254740993", matcher: "match github id exact 9007199254740993", wantID: "9007199254740993", allow: true},
		{name: "large neighbor", id: "9007199254740992", matcher: "match github id exact 9007199254740993", wantID: "9007199254740992"},
		{name: "maximum integer", id: "18446744073709551615", matcher: "match github id exact 18446744073709551615", wantID: "18446744073709551615", allow: true},
		{name: "missing ID cannot use spoofed claim", matcher: "match github id regex .*"},
		{name: "zero", id: "0", reject: true},
		{name: "negative", id: "-1", reject: true},
		{name: "null", id: "null", reject: true},
		{name: "fraction", id: "123.5", reject: true},
		{name: "string", id: `"123"`, reject: true},
		{name: "overflow", id: "18446744073709551616", reject: true},
		{name: "other driver named github", driver: "linkedin", realm: "github", id: "123", matcher: "match github id exact 123"},
		{name: "ID and org", id: "123", wantID: "123", matcher: "match github id exact 123", additionalMatcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"acme"}]`, wantOrgs: []string{"acme"}, allow: true},
		{name: "ID and org wrong ID", id: "124", wantID: "124", matcher: "match github id exact 123", additionalMatcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"acme"}]`, wantOrgs: []string{"acme"}},
		{name: "ID and org wrong org", id: "123", wantID: "123", matcher: "match github id exact 123", additionalMatcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"other"}]`, wantOrgs: []string{"other"}},
		{name: "organization exact", matcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"other"},{"login":"acme"}]`, wantOrgs: []string{"other", "acme"}, allow: true},
		{name: "organization regex", matcher: "match github org regex ^acme(-labs)?$", orgFilter: ".*", orgBody: `[{"login":"acme-labs"}]`, wantOrgs: []string{"acme-labs"}, allow: true},
		{name: "organization miss", matcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"acme-labs"}]`, wantOrgs: []string{"acme-labs"}},
		{name: "organization regex miss", matcher: "match github org regex ^acme$", orgFilter: ".*", orgBody: `[{"login":"my-acme"}]`, wantOrgs: []string{"my-acme"}},
		{name: "organization filtered", matcher: "match github org exact acme", orgFilter: "^other$", orgBody: `[{"login":"acme"},{"login":"other"}]`, wantOrgs: []string{"other"}},
		{name: "organization lookup not enabled", matcher: "match github org regex .*"},
		{name: "no memberships", matcher: "match github org regex .*", orgFilter: ".*", orgBody: `[]`},
		{name: "malformed organization login", matcher: "match github org regex .*", orgFilter: ".*", orgBody: `[{"login":123},{"login":null},{"login":""}]`},
		{name: "organization API denial", matcher: "match github org regex .*", orgFilter: ".*", orgStatus: 403, orgBody: `[{"login":"acme"}]`},
		{name: "organization malformed JSON", matcher: "match github org regex .*", orgFilter: ".*", orgBody: `{`},
		{name: "other driver organization spoof", driver: "linkedin", realm: "github", matcher: "match github org exact acme", orgFilter: ".*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.login == "" {
				tc.login = "alice"
			}
			if tc.driver == "" {
				tc.driver = "github"
			}
			if tc.realm == "" {
				tc.realm = "engineering"
			}
			if tc.matcher == "" {
				tc.matcher = "match github id regex .*"
			}
			mu.Lock()
			scenario, exchanges, profiles, organizations = tc, 0, 0, 0
			mu.Unlock()
			p := newGithubTransformPortal(t, upstream, proxy, tc)
			mu.Lock()
			callback = p.server.URL + p.base + "/oauth2/" + tc.realm + "/authorization-code-callback"
			mu.Unlock()
			want := http.StatusSeeOther
			if tc.reject {
				want = http.StatusUnauthorized
			}
			token, _ := p.login(t, want)
			mu.Lock()
			gotExchanges, gotProfiles, gotOrgs := exchanges, profiles, organizations
			mu.Unlock()
			if gotExchanges != 1 || gotProfiles != 1 {
				t.Fatal("OAuth exchange and profile fetch were not exercised")
			}
			if tc.reject {
				return
			}
			parsed, err := jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return []byte(oidcE2EPortalSecret), nil },
				jwtlib.WithValidMethods([]string{"HS512"}), jwtlib.WithExpirationRequired(), jwtlib.WithJSONNumber())
			if err != nil || !parsed.Valid {
				t.Fatal("portal token failed independent verification")
			}
			claims := parsed.Claims.(jwtlib.MapClaims)
			id, hasID := claims["github_id"]
			if hasID != (tc.wantID != "") || (hasID && id != tc.wantID) {
				t.Fatal("incorrect GitHub ID in signed claims")
			}
			if tc.driver == "github" {
				if claims["sub"] != "github.com/"+tc.login {
					t.Fatal("existing subject behavior changed")
				}
				if tc.wantID != "" {
					metadata, ok := claims["metadata"].(map[string]any)
					if !ok || metadata["id"] != json.Number(tc.wantID) {
						t.Fatal("numeric metadata ID lost precision or changed type")
					}
				}
			}
			var orgs []string
			if values, exists := claims["github_orgs"]; exists {
				list, ok := values.([]any)
				if !ok {
					t.Fatal("organization claim is not a list")
				}
				for _, value := range list {
					orgs = append(orgs, value.(string))
				}
			}
			if !reflect.DeepEqual(orgs, tc.wantOrgs) {
				t.Fatalf("organizations = %v, want %v", orgs, tc.wantOrgs)
			}
			wantOrgCalls := 0
			if tc.driver == "github" && tc.orgFilter != "" {
				wantOrgCalls = 1
			}
			if gotOrgs != wantOrgCalls {
				t.Fatalf("organization API calls = %d, want %d", gotOrgs, wantOrgCalls)
			}
			status, body := p.get(t, "/protected", token)
			if tc.allow {
				if status != http.StatusOK || string(body) != "protected-resource" {
					t.Fatalf("matching user denied: HTTP %d", status)
				}
			} else if status == http.StatusOK || strings.Contains(string(body), "protected-resource") {
				t.Fatal("nonmatching user accessed the protected resource")
			}
		})
	}
}

func newGithubTransformPortal(t *testing.T, upstream, proxy *httptest.Server, tc githubTransformCase) *oidcE2EPortal {
	t.Helper()
	directives := []string{}
	add := func(args ...string) { directives = append(directives, cfgutil.EncodeArgs(args)) }
	add("driver", tc.driver)
	add("realm", tc.realm)
	add("client_id", oidcE2EClientID)
	add("client_secret", oidcE2EClientSecret)
	add("base_auth_url", upstream.URL)
	add("tls", "verification", "disabled") // Local fixture certificate only.
	if tc.driver == "linkedin" {
		add("metadata_url", upstream.URL+"/metadata")
		add("key", "verification", "disabled")
	}
	if tc.orgFilter != "" {
		add("user_org_filters", tc.orgFilter)
	}
	providerConfig, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", directives)
	if err != nil {
		t.Fatal(err)
	}
	var restored idp.IdentityProviderConfig
	if err := json.Unmarshal(oidcE2EJSON(t, providerConfig), &restored); err != nil {
		t.Fatal(err)
	}
	provider, err := idp.NewIdentityProvider(&restored, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.(*oauth.IdentityProvider).Close)
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}
	statements := []string{tc.matcher, "match realm " + tc.realm, "action add role github-member"}
	if tc.additionalMatcher != "" {
		statements = append(statements, tc.additionalMatcher)
	}
	cfg, err := transformparser.NewUserTransformerConfigFromDirectives(statements)
	if err != nil {
		t.Fatal(err)
	}
	var transformConfig transformer.Config
	if err := json.Unmarshal(oidcE2EJSON(t, cfg), &transformConfig); err != nil {
		t.Fatal(err)
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{"path": newJWKSE2EDatabase(t), "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	keys := []string{"crypto default token name oauth_portal_token", "crypto default token lifetime 300", "crypto key portal-hmac sign-verify " + oidcE2EPortalSecret}
	cookies := cookie.NewConfig()
	cookies.AccessTokenCookieName = "oauth_portal_token"
	portal, err := authn.NewPortal(authn.PortalParameters{
		Config: &authn.PortalConfig{Name: "github-transform", IdentityStores: []string{"local"}, IdentityProviders: []string{"upstream"}, RawCryptoKeyStoreConfig: keys, CookieConfig: cookies, UserTransformerConfigs: []*transformer.Config{&transformConfig}},
		Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}, IdentityProviders: []idp.IdentityProvider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(portal.Close)
	gate, err := authz.NewGatekeeper(&authz.PolicyConfig{Name: "github-transform", AuthURLPath: "/auth/login", ValidateBearerHeader: true, RawCryptoKeyStoreConfig: keys, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles github-member"}, Action: "allow stop"}}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protected" {
			ar := requests.NewAuthorizationRequest()
			_ = gate.Authenticate(w, r, ar)
			if ar.Response.Authorized {
				_, _ = io.WriteString(w, "protected-resource")
			}
			return
		}
		_ = portal.ServeHTTP(r.Context(), w, r, requests.NewRequest())
	}))
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	pool.AddCert(upstream.Certificate())
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, Proxy: func(r *http.Request) (*url.URL, error) {
		if r.URL.Hostname() == "127.0.0.1" {
			return nil, nil
		}
		return proxyURL, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &oidcE2EPortal{server: server, base: "/auth", realm: tc.realm, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func githubFixtureCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"github.com", "api.github.com", "api.linkedin.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newGithubTransformProxy(t *testing.T, target string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	var workers sync.WaitGroup
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || (r.Host != "github.com:443" && r.Host != "api.github.com:443" && r.Host != "api.linkedin.com:443") {
			http.Error(w, "proxy target rejected", http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			http.Error(w, "upstream unavailable", 502)
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
		connections[client], connections[upstream] = true, true
		workers.Add(1)
		mu.Unlock()
		_, _ = fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			defer workers.Done()
			done := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
			_, _ = io.Copy(client, upstream)
			client.Close()
			upstream.Close()
			<-done
			mu.Lock()
			delete(connections, client)
			delete(connections, upstream)
			mu.Unlock()
		}()
	}))
	t.Cleanup(func() {
		proxy.Close()
		mu.Lock()
		for connection := range connections {
			connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return proxy
}
