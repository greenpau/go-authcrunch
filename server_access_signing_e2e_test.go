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
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

type selectedRootTLS struct {
	mu             sync.RWMutex
	root           *authcrunch.Server
	server         *httptest.Server
	key, auxiliary *fixture.Fixture
	config         []byte
}

func newSelectedRootTLS(t *testing.T, persistent bool) *selectedRootTLS {
	t.Helper()
	f := &selectedRootTLS{}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		defer f.mu.RUnlock()
		if r.URL.Path == "/protected" {
			g, err := f.root.GetGatekeeperByName("resource")
			ar := requests.NewAuthorizationRequest()
			if err != nil || g.Authenticate(w, r, ar) != nil || !ar.Response.Authorized {
				http.Error(w, "denied", 401)
				return
			}
			w.WriteHeader(204)
			return
		}
		p, err := f.root.GetPortalByName("selected")
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		if err := p.ServeHTTPAt(r.Context(), w, r, requests.NewRequest(), "/auth"); err != nil {
			t.Error("selected portal request failed")
		}
	}))
	origin := "https://" + f.server.Listener.Addr().String()
	f.key = fixture.New(t, origin+"/auth")
	f.auxiliary = fixture.New(t, origin+"/auth")
	dbpath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal(err)
	}
	cookies := cookie.NewConfig()
	cookies.AccessTokenCookieName = "WIRE_ACCESS"
	cookies.Lifetime = 3600
	raw := []string{"crypto default token name LOGICAL", "crypto default token lifetime 60", "crypto key current verify from file " + f.key.PublicFile}
	cfg := &authcrunch.Config{ExternalAccessSigners: []*kms.ExternalAccessSignerConfig{f.key.Descriptor}, IdentityStores: []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local", Params: map[string]any{"path": dbpath, "realm": "local"}}}, AuthenticationPortals: []*authn.PortalConfig{{Name: "selected", IdentityStores: []string{"accounts"}, AccessSigner: "access", AccessTokenProfile: f.key.Profile.Clone(), RawCryptoKeyStoreConfig: raw, CookieConfig: cookies, RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: origin, BasePath: "/auth", BodyTransportEnabled: true, AccessLifetimeSeconds: 300}, UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"match roles authp/user"}, Actions: []string{"add audience api"}}}}}, AuthorizationPolicies: []*authz.PolicyConfig{{Name: "resource", AccessTokenProfile: f.key.Profile.Clone(), RawCryptoKeyStoreConfig: raw, ValidateBearerHeader: true, AuthRedirectDisabled: true, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}, {Name: "auxiliary", AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}, AccessTokenProfile: f.auxiliary.Profile.Clone(), RawCryptoKeyStoreConfig: []string{"crypto key current verify from file " + f.auxiliary.PublicFile}}}}
	if persistent {
		cfg.State = &state.Config{Directory: filepath.Join(t.TempDir(), "runtime")}
	}
	f.config = fixture.JSON(t, cfg)
	f.start(t)
	f.server.StartTLS()
	f.server.Client().Timeout = 10 * time.Second
	t.Cleanup(func() { f.server.Close(); f.stop(t) })
	return f
}
func (f *selectedRootTLS) start(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var cfg authcrunch.Config
	if json.Unmarshal(f.config, &cfg) != nil {
		t.Fatal("configuration snapshot failed")
	}
	root, err := authcrunch.NewServerWithOptions(&cfg, zap.NewNop(), authcrunch.ServerOptions{AccessSigners: map[string]kms.AccessSigner{"access": f.key.Signer}})
	if err != nil {
		t.Fatal("selected root construction failed", err)
	}
	f.root = root
}
func (f *selectedRootTLS) stop(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.root != nil {
		if err := f.root.Close(); err != nil {
			t.Error("selected root close failed")
		}
		f.root = nil
	}
}
func (f *selectedRootTLS) request(t *testing.T, method, path string, body any, token string, browser bool) (int, http.Header, []byte) {
	t.Helper()
	var data []byte
	if body != nil {
		data = fixture.JSON(t, body)
	}
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal("request construction failed")
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if browser {
		r.Header.Set("Origin", f.server.URL)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("X-Authcrunch-Refresh", "1")
	}
	response, err := f.server.Client().Do(r)
	if err != nil {
		t.Fatal("trusted TLS request failed")
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("TLS peer was not verified")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
	if err != nil {
		t.Fatal("response read failed")
	}
	return response.StatusCode, response.Header, raw
}
func (f *selectedRootTLS) login(t *testing.T, transport string) apiauth.AuthResponse {
	t.Helper()
	browser := transport == "cookie"
	status, _, data := f.request(t, "POST", "/auth/login", apiauth.AuthRequest{Username: "alice", Realm: "local", RefreshTransport: transport}, "", browser)
	var first apiauth.AuthResponse
	if status != 200 || json.Unmarshal(data, &first) != nil || first.SandboxID == "" || first.SandboxSecret == "" {
		t.Fatal("initial real password checkpoint failed")
	}
	status, headers, data := f.request(t, "POST", "/auth/login", apiauth.AuthRequest{Username: "alice", Realm: "local", RefreshTransport: transport, SandboxID: first.SandboxID, SandboxSecret: first.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1}, "", browser)
	var result apiauth.AuthResponse
	if status != 200 || headers.Get("Cache-Control") != "no-store" || json.Unmarshal(data, &result) != nil || !result.Authenticated {
		t.Fatal("password completion failed")
	}
	if browser {
		found := false
		for _, raw := range headers.Values("Set-Cookie") {
			c, err := http.ParseSetCookie(raw)
			if err != nil {
				t.Fatal("cookie parse failed")
			}
			if c.Name == "WIRE_ACCESS" && c.Value != "" && c.MaxAge > 0 {
				found = true
				if !c.Secure || !c.HttpOnly || c.MaxAge > 60 {
					t.Fatal("browser access cookie outlived signed grant")
				}
			}
		}
		if !found || result.AccessToken != "" || result.RefreshToken != "" {
			t.Fatal("browser credentials crossed transport")
		}
	} else if result.AccessTokenName != "WIRE_ACCESS" || result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("native token labels or credentials missing")
	}
	return result
}
func (f *selectedRootTLS) refresh(t *testing.T, raw string, want int) apiauth.AuthResponse {
	t.Helper()
	status, headers, data := f.request(t, "POST", "/auth/api/refresh_token", map[string]string{"refresh_token": raw}, "", false)
	if status != want || headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("refresh HTTP %d, want %d", status, want)
	}
	var result apiauth.AuthResponse
	if json.Unmarshal(data, &result) != nil {
		t.Fatal("invalid refresh JSON")
	}
	if want != 200 && (result.AccessToken != "" || result.RefreshToken != "" || len(headers.Values("Set-Cookie")) != 0) {
		t.Fatal("failed native refresh published credentials")
	}
	return result
}
func TestE2EServerSelectedAccessSigning(t *testing.T) {
	f := newSelectedRootTLS(t, false)
	first := f.login(t, "body")
	status, headers, public := f.request(t, "GET", "/auth/.well-known/jwks.json", nil, "", false)
	if status != 200 || headers.Get("Content-Type") != "application/jwk-set+json" || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("public profile discovery failed")
	}
	var document struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			Algorithm string `json:"alg"`
			KeyID     string `json:"kid"`
			N         string `json:"n"`
			E         string `json:"e"`
		} `json:"keys"`
	}
	if json.Unmarshal(public, &document) != nil || len(document.Keys) != 1 || document.Keys[0].Algorithm != "PS256" || document.Keys[0].KeyID != "current" {
		t.Fatal("public selected key mismatch")
	}
	n, err := base64.RawURLEncoding.DecodeString(document.Keys[0].N)
	if err != nil {
		t.Fatal("public modulus malformed")
	}
	e, err := base64.RawURLEncoding.DecodeString(document.Keys[0].E)
	if err != nil {
		t.Fatal("public exponent malformed")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	parts := strings.Split(first.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatal("issued compact token malformed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32}) != nil {
		t.Fatal("independent public verification failed")
	}
	if status, _, _ := f.request(t, "GET", "/protected", nil, first.AccessToken, false); status != 204 {
		t.Fatal("actual gatekeeper rejected selected token")
	}
	if status, h, body := f.request(t, "HEAD", "/auth/.well-known/jwks.json", nil, "", false); status != 200 || len(body) != 0 || h.Get("Content-Length") != headers.Get("Content-Length") {
		t.Fatal("selected JWKS HEAD contract failed")
	}
	next := f.refresh(t, first.RefreshToken, 200)
	claims, err := f.key.Store(t).VerifyAccessToken(t.Context(), next.AccessToken)
	if err != nil || claims["exp"] != json.Number(fmtInt(next.AccessExpiresAt)) {
		t.Fatal("refresh expiry differs from signed grant")
	}
	f.refresh(t, first.RefreshToken, 401)
	f.refresh(t, next.RefreshToken, 401)
	f.login(t, "cookie")
}
func fmtInt(n int64) string { return new(big.Int).SetInt64(n).String() }
func TestE2EServerSelectedAccessPersistenceTrust(t *testing.T) {
	f := newSelectedRootTLS(t, true)
	first := f.login(t, "body")
	f.stop(t)
	// A byte-different encoding of exactly the loaded public authority keeps the epoch.
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&f.auxiliary.Key.PublicKey)})
	if err := os.WriteFile(f.auxiliary.PublicFile, pkcs1, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	same := f.refresh(t, first.RefreshToken, 200)
	// This verifier belongs only to a policy. Changing its loaded key at the same
	// pathname must retire the whole root epoch, including portal refresh families.
	f.stop(t)
	replacement := fixture.New(t, f.key.Profile.Issuer)
	other, err := os.ReadFile(replacement.PublicFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.auxiliary.PublicFile, other, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	f.refresh(t, same.RefreshToken, 401)
	fresh := f.login(t, "body")
	f.refresh(t, fresh.RefreshToken, 200)
	f.stop(t)
	if err := os.WriteFile(f.auxiliary.PublicFile, pkcs1, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	f.refresh(t, same.RefreshToken, 401)
	control := f.login(t, "body")
	f.refresh(t, control.RefreshToken, 200)
}
