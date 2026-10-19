// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	storage "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
	storageparser "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite/parser"
	"go.uber.org/zap"
)

// Each replica has a distinct adapter and database connection. Fault controls
// are test-only and failures intentionally contain text that must be redacted.
type loginFaultStore struct {
	oauth.LoginStore
	phase atomic.Int32
	peer  oauth.LoginStore
}

func (s *loginFaultStore) Create(c context.Context, n string, v oauth.LoginTransaction) error {
	if s.phase.Load() == 1 {
		return errors.New("private-backend-diagnostic")
	}
	if s.phase.Load() == 8 {
		// Model an initiating replica whose clock is one second ahead.
		v.CreatedAt++
		v.ExpiresAt++
	}
	if s.phase.Load() == 9 {
		// Model bounded private evidence that fills the pending record's JSON
		// budget, leaving no room for the claim added by the callback replica.
		v.ReturnURL = "/" + strings.Repeat("&", 10000)
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		v.ReturnURL += strings.Repeat("a", 65536-len(encoded))
	}
	return s.LoginStore.Create(c, n, v)
}
func (s *loginFaultStore) Claim(c context.Context, n, k string, b oauth.LoginBinding, claim string) (oauth.LoginTransaction, error) {
	if s.phase.Load() == 2 {
		return oauth.LoginTransaction{}, errors.New("private-backend-diagnostic")
	}
	value, err := s.LoginStore.Claim(c, n, k, b, claim)
	if err == nil && s.phase.Load() == 6 {
		// Simulate a committed claim whose acknowledgement was lost. Even
		// tentative evidence accompanying the error must never be trusted.
		return value, errors.New("private-backend-diagnostic")
	}
	return value, err
}
func (s *loginFaultStore) Get(c context.Context, n, k string) (oauth.LoginTransaction, error) {
	if s.phase.Load() == 3 {
		return oauth.LoginTransaction{}, errors.New("private-backend-diagnostic")
	}
	return s.LoginStore.Get(c, n, k)
}
func (s *loginFaultStore) Complete(c context.Context, n, k, claim string) error {
	if s.phase.Load() == 4 {
		return errors.New("private-backend-diagnostic")
	}
	if s.phase.Load() == 5 {
		v, e := s.peer.Get(c, n, k)
		if e != nil {
			return e
		}
		if _, e = s.peer.Cancel(c, n, k, v.Binding); e != nil {
			return e
		}
	}
	err := s.LoginStore.Complete(c, n, k, claim)
	if err == nil && s.phase.Load() == 7 {
		return errors.New("private-backend-diagnostic")
	}
	return err
}

func (s *loginFaultStore) Close() error {
	if closer, ok := s.LoginStore.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

type sharedOAuthFixture struct {
	lb, upstream *httptest.Server
	nodes        [2]*authcrunch.Server
	stores       [2]*storage.Store
	adapters     [2]*loginFaultStore
	client       *http.Client
	exchanges    atomic.Int32
}
type sharedOAuthResponse struct {
	status int
	header http.Header
	body   []byte
}

// This portable fixture uses only public APIs and is also run in an external
// module. The root owns composition; SQLite proves a real backend contract.
func newSharedOAuthFixture(t *testing.T, configure ...func(int, *authcrunch.Config)) *sharedOAuthFixture {
	t.Helper()
	f := &sharedOAuthFixture{}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(claims map[string]any) string {
		h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "upstream"})
		p, _ := json.Marshal(claims)
		input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
		return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
	}
	var mu sync.Mutex
	pending := make(map[string]url.Values)
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/metadata":
			json.NewEncoder(w).Encode(map[string]any{"issuer": f.upstream.URL, "authorization_endpoint": f.upstream.URL + "/authorize", "token_endpoint": f.upstream.URL + "/token", "jwks_uri": f.upstream.URL + "/keys"})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "upstream", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(public)}}})
		case "/authorize":
			q := r.URL.Query()
			if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" {
				http.Error(w, "invalid initiation", 400)
				return
			}
			pending[q.Get("state")] = q
			http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"state": {q.Get("state")}, "code": {q.Get("state") + "-code"}}.Encode(), 302)
		case "/token":
			f.exchanges.Add(1)
			if r.ParseForm() != nil {
				w.WriteHeader(400)
				return
			}
			state := r.Form.Get("state")
			q, ok := pending[state]
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || r.Form.Get("code") != state+"-code" || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "synthetic-secret" || r.Form.Get("redirect_uri") != q.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(challenge[:]) != q.Get("code_challenge") {
				http.Error(w, "invalid exchange", 400)
				return
			}
			delete(pending, state)
			token := sign(map[string]any{"iss": f.upstream.URL, "aud": "client", "sub": "external-user", "email": "external@example.test", "name": "External User", "roles": []string{"authp/user"}, "nonce": q.Get("nonce"), "exp": time.Now().Add(time.Hour).Unix()})
			json.NewEncoder(w).Encode(map[string]any{"id_token": token, "access_token": "opaque", "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.upstream.Close)
	f.lb = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node, _ := strconv.Atoi(r.Header.Get("X-Test-Replica"))
		if node < 0 || node > 1 {
			w.WriteHeader(400)
			return
		}
		runtime := f.nodes[node]
		if r.URL.Path == "/protected" {
			gate, err := runtime.GetGatekeeperByName("policy")
			if err != nil {
				w.WriteHeader(503)
				return
			}
			rr := requests.NewAuthorizationRequest()
			if gate.Authenticate(w, r, rr) != nil {
				w.WriteHeader(401)
				return
			}
			if rr.Response.Authorized {
				w.WriteHeader(204)
			}
			return
		}
		portal, err := runtime.GetPortalByName("portal")
		if err != nil {
			w.WriteHeader(503)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("portal failed")
		}
	}))
	origin := "https://" + f.lb.Listener.Addr().String()
	// Portal credentials use a separate authority from the upstream ID token;
	// protected-resource acceptance must prove portal issuance.
	portalPublic, portalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(portalPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "sign.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(portalPublic)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "verify.pem")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0600); err != nil {
		t.Fatal(err)
	}
	backend, err := storageparser.NewSQLiteOAuthLoginStoreConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "logins.db")}), "capacity 100", "timeout 2s"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.nodes {
		f.stores[i], err = storage.New(t.Context(), backend)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.stores[i].Close() })
		f.adapters[i] = &loginFaultStore{LoginStore: f.stores[i]}
		statements := []string{"realm upstream", "driver generic", "client id client", "client secret synthetic-secret", cfgutil.EncodeArgs([]string{"base", "auth", "url", f.upstream.URL}), cfgutil.EncodeArgs([]string{"metadata", "url", f.upstream.URL + "/metadata"}), "tls verification disabled", "login store shared namespace cluster"}
		provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", statements)
		if err != nil {
			t.Fatal(err)
		}
		c := &authcrunch.Config{IdentityProviders: []*idp.IdentityProviderConfig{provider}, AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityProviders: []string{"upstream"}, RawCryptoKeyStoreConfig: []string{cfgutil.EncodeArgs([]string{"crypto", "key", "shared", "sign-verify", "from", "file", keyPath})}}}, AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", ValidateBearerHeader: true, AuthRedirectDisabled: true, RawCryptoKeyStoreConfig: []string{cfgutil.EncodeArgs([]string{"crypto", "key", "shared", "verify", "from", "file", pubPath})}, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}}}
		for _, apply := range configure {
			apply(i, c)
		}
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var restored authcrunch.Config
		if json.Unmarshal(data, &restored) != nil {
			t.Fatal("decode configuration")
		}
		if i == 0 {
			if runtime, err := authcrunch.NewServer(&restored, zap.NewNop()); err == nil {
				runtime.Close()
				t.Fatal("missing named backend fell back to memory")
			}
			if json.Unmarshal(data, &restored) != nil {
				t.Fatal("decode configuration")
			}
		}
		f.nodes[i], err = authcrunch.NewServerWithOptions(&restored, zap.NewNop(), authcrunch.ServerOptions{OAuthLoginStores: map[string]oauth.LoginStore{"shared": f.adapters[i]}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.nodes[i].Close(); err != nil {
				t.Error(err)
			}
		})
	}
	f.adapters[0].peer = f.stores[1]
	f.adapters[1].peer = f.stores[0]
	f.lb.StartTLS()
	t.Cleanup(f.lb.Close)
	if f.lb.URL != origin {
		t.Fatal("public origin changed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.lb.Certificate())
	roots.AddCert(f.upstream.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Transport: transport, Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}
func (f *sharedOAuthFixture) request(t *testing.T, client *http.Client, node int, target, token string) sharedOAuthResponse {
	t.Helper()
	response, err := f.doRequest(t.Context(), client, node, target, token)
	if err != nil {
		t.Fatal("request failed")
	}
	return response
}
func (f *sharedOAuthFixture) doRequest(ctx context.Context, client *http.Client, node int, target, token string) (sharedOAuthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return sharedOAuthResponse{}, err
	}
	req.Header.Set("X-Test-Replica", strconv.Itoa(node))
	req.Header.Set("Accept", "text/html")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return sharedOAuthResponse{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return sharedOAuthResponse{}, err
	}
	return sharedOAuthResponse{resp.StatusCode, resp.Header, data}, nil
}
func (f *sharedOAuthFixture) start(t *testing.T, node int) string {
	t.Helper()
	f.client.Jar, _ = cookiejar.New(nil)
	started := f.request(t, f.client, node, f.lb.URL+"/auth/oauth2/upstream", "")
	if started.status != 302 {
		t.Fatalf("start: HTTP %d", started.status)
	}
	authorized := f.request(t, f.client, node, started.header.Get("Location"), "")
	if authorized.status != 302 {
		t.Fatalf("authorize: HTTP %d", authorized.status)
	}
	return authorized.header.Get("Location")
}
func sharedOAuthDenied(t *testing.T, r sharedOAuthResponse, status int) {
	t.Helper()
	if r.status != status || r.header.Get("Authorization") != "" || r.header.Get("Location") != "" || strings.Contains(string(r.body), "private-backend-diagnostic") {
		t.Fatalf("denial: HTTP %d, expected %d without credentials or diagnostics", r.status, status)
	}
	for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
		if strings.Contains(cookie.Name, "ACCESS_TOKEN") && cookie.MaxAge >= 0 {
			t.Fatal("denied response issued access cookie")
		}
	}
}

func TestE2EServerSharedOAuthLogin(t *testing.T) {
	f := newSharedOAuthFixture(t)
	for start := range 2 {
		if start == 1 {
			f.adapters[start].phase.Store(8)
		}
		callback := f.start(t, start)
		f.adapters[start].phase.Store(0)
		stranger := *f.client
		stranger.Jar, _ = cookiejar.New(nil)
		sharedOAuthDenied(t, f.request(t, &stranger, 1-start, callback, ""), 401)
		completed := f.request(t, f.client, 1-start, callback, "")
		if completed.status != 303 {
			t.Fatalf("cross-replica completion: HTTP %d", completed.status)
		}
		token := strings.TrimPrefix(completed.header.Get("Authorization"), "Bearer ")
		if token == "" {
			t.Fatal("no portal token")
		}
		for node := range 2 {
			if r := f.request(t, f.client, node, f.lb.URL+"/protected", token); r.status != 204 {
				t.Fatalf("protected replica %d: HTTP %d", node, r.status)
			}
		}
		sharedOAuthDenied(t, f.request(t, f.client, start, callback, ""), 401)
	}
	callback := f.start(t, 0)
	before := f.exchanges.Load()
	responses := make(chan sharedOAuthResponse, 2)
	for node := range 2 {
		go func() {
			response, err := f.doRequest(t.Context(), f.client, node, callback, "")
			if err != nil {
				t.Error("concurrent callback request failed")
			}
			responses <- response
		}()
	}
	a, b := <-responses, <-responses
	if !((a.status == 303 && b.status == 401) || (a.status == 401 && b.status == 303)) || f.exchanges.Load()-before != 1 {
		t.Fatal("duplicate callback admitted more than once")
	}
	// Draining and closing one root must not close its borrowed store or remove
	// a pending transaction that the second root can finish.
	callback = f.start(t, 0)
	if err := f.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stores[0].Get(t.Context(), "ownership-probe", "missing"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("root closed a host-owned store")
	}
	if r := f.request(t, f.client, 1, callback, ""); r.status != 303 {
		t.Fatalf("peer shutdown lost login: HTTP %d", r.status)
	}
}

func TestE2EServerSharedOAuthStorageFailures(t *testing.T) {
	f := newSharedOAuthFixture(t)
	for _, phase := range []int32{1, 9} {
		f.adapters[0].phase.Store(phase)
		sharedOAuthDenied(t, f.request(t, f.client, 0, f.lb.URL+"/auth/oauth2/upstream", ""), 503)
	}
	f.adapters[0].phase.Store(0)
	for _, phase := range []int32{2, 3, 4, 5, 6, 7} {
		callback := f.start(t, 0)
		f.adapters[1].phase.Store(phase)
		status := 503
		if phase == 5 {
			status = 401
		}
		sharedOAuthDenied(t, f.request(t, f.client, 1, callback, ""), status)
		f.adapters[1].phase.Store(0)
		retry := f.request(t, f.client, 0, callback, "")
		if phase == 2 {
			if retry.status != 303 {
				t.Fatal("unclaimed login lost after backend recovery")
			}
		} else {
			sharedOAuthDenied(t, retry, 401)
		}
	}
}

func TestE2EServerSharedOAuthIsolation(t *testing.T) {
	for _, setting := range []string{"namespace", "trust configuration"} {
		t.Run(setting, func(t *testing.T) {
			f := newSharedOAuthFixture(t, func(node int, c *authcrunch.Config) {
				if node != 1 {
					return
				}
				if setting == "namespace" {
					c.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "shared", "namespace": "another-deployment"}
				} else {
					c.IdentityProviders[0].Params["nonce_disabled"] = true
				}
			})
			callback := f.start(t, 0)
			before := f.exchanges.Load()
			sharedOAuthDenied(t, f.request(t, f.client, 1, callback, ""), 401)
			if f.exchanges.Load() != before {
				t.Fatal("isolated provider exchanged code")
			}
			if got := f.request(t, f.client, 0, callback, ""); got.status != 303 {
				t.Fatal("isolated attempt consumed legitimate login")
			}
		})
	}
}
