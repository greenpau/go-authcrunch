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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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

	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const (
	oidcE2EClientID     = "oauth-e2e-client"
	oidcE2EClientSecret = "synthetic-oauth-e2e-secret"
	oidcE2EPortalSecret = "synthetic-independent-portal-secret"
)

type oidcE2ECode struct{ state, nonce, challenge, redirect, subject string }

// The synthetic upstream speaks the public OAuth protocol. Its signatures are
// produced with crypto/ed25519 or crypto/rsa, not the adapter being exercised.
type oidcE2EIssuer struct {
	server                                                      *httptest.Server
	mu                                                          sync.Mutex
	private                                                     ed25519.PrivateKey
	rsaPrivate                                                  *rsa.PrivateKey
	keys                                                        []map[string]string
	keyID, algorithm, accessMode, failure, callback             string
	codes                                                       map[string]oidcE2ECode
	accessSubjects                                              map[string]string
	sequence, metadataFetches, keyFetches, exchanges, userInfos int
	lastIdentity, lastSubject                                   string
}

func oidcE2EJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newOIDCE2EIssuer(t *testing.T, algorithm, accessMode, failure string, mixed bool) *oidcE2EIssuer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcE2EIssuer{private: private, rsaPrivate: rsaPrivate, keyID: "upstream-ed", algorithm: algorithm, accessMode: accessMode, failure: failure, codes: make(map[string]oidcE2ECode), accessSubjects: make(map[string]string)}
	edKey := map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": f.keyID, "x": base64.RawURLEncoding.EncodeToString(public), "use": "sig"}
	if mixed {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.keys = []map[string]string{
			{"kty": "RSA", "kid": "upstream-rsa", "n": base64.RawURLEncoding.EncodeToString(rsaPrivate.N.Bytes()), "e": "AQAB", "alg": "RS256", "use": "sig"},
			{"kty": "EC", "kid": "upstream-ec", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(ec.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(ec.Y.FillBytes(make([]byte, 32)))},
			{"kty": "OKP", "kid": "unsupported-curve", "crv": "X25519", "x": base64.RawURLEncoding.EncodeToString(public)},
		}
	}
	f.keys = append(f.keys, edKey)
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	t.Cleanup(f.server.Close)
	return f
}

func (f *oidcE2EIssuer) sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	id := f.keyID
	if alg == "RS256" {
		id = "upstream-rsa"
	}
	header := map[string]any{"alg": alg, "kid": id, "typ": "JWT"}
	if f.failure == "missing kid" {
		delete(header, "kid")
	}
	if f.failure == "unknown kid" {
		header["kid"] = "unknown"
	}
	input := base64.RawURLEncoding.EncodeToString(oidcE2EJSON(t, header)) + "." + base64.RawURLEncoding.EncodeToString(oidcE2EJSON(t, claims))
	var signature []byte
	if alg == "RS256" {
		hash := sha256.Sum256([]byte(input))
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, f.rsaPrivate, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
	} else {
		signature = ed25519.Sign(f.private, []byte(input))
	}
	if f.failure == "signature" {
		signature[0] ^= 1
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *oidcE2EIssuer) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		f.metadataFetches++
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "userinfo_endpoint": f.server.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256", "EdDSA", "Ed25519", "future-algorithm"}})
	case "/jwks":
		f.keyFetches++
		json.NewEncoder(w).Encode(map[string]any{"keys": f.keys})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != oidcE2EClientID || q.Get("redirect_uri") != f.callback || q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			t.Error("authorization request violated OAuth contract")
			http.Error(w, "bad authorization request", 400)
			return
		}
		f.sequence++
		code := fmt.Sprintf("synthetic-code-%d", f.sequence)
		f.codes[code] = oidcE2ECode{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: f.callback, subject: fmt.Sprintf("upstream-user-%d", f.sequence)}
		params := url.Values{"state": {q.Get("state")}, "code": {code}}
		if f.failure == "state" {
			params.Set("state", "unknown-state")
		}
		http.Redirect(w, r, f.callback+"?"+params.Encode(), http.StatusFound)
	case "/token":
		if r.Method != http.MethodPost || r.ParseForm() != nil {
			t.Error("invalid token request")
			http.Error(w, "bad token request", 400)
			return
		}
		record, exists := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !exists || r.Form.Get("client_id") != oidcE2EClientID || r.Form.Get("client_secret") != oidcE2EClientSecret || r.Form.Get("redirect_uri") != record.redirect || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("state") != record.state || base64.RawURLEncoding.EncodeToString(challenge[:]) != record.challenge {
			t.Error("code exchange violated state, client, redirect, or PKCE binding")
			http.Error(w, "bad code exchange", 400)
			return
		}
		f.exchanges++
		claims := map[string]any{"iss": f.server.URL, "aud": oidcE2EClientID, "sub": record.subject, "email": record.subject + "@example.test", "name": "OAuth User", "nonce": record.nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"viewer"}}
		switch f.failure {
		case "issuer":
			claims["iss"] = "https://wrong.example"
		case "audience":
			claims["aud"] = "wrong-client"
		case "nonce":
			claims["nonce"] = "wrong-nonce"
		case "nonce type":
			claims["nonce"] = 17
		case "expired":
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
		}
		id := f.sign(t, f.algorithm, claims)
		access := "opaque-" + record.subject
		if f.accessMode == "jwt" {
			accessClaims := map[string]any{"iss": f.server.URL, "aud": "resource-api", "azp": oidcE2EClientID, "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"editor"}}
			access = f.sign(t, "Ed25519", accessClaims)
		}
		f.accessSubjects[access] = record.subject
		f.lastIdentity = id
		f.lastSubject = record.subject
		json.NewEncoder(w).Encode(map[string]any{"id_token": id, "access_token": access, "token_type": "Bearer", "expires_in": 3600})
	case "/userinfo":
		subject, exists := f.accessSubjects[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !exists {
			t.Error("userinfo did not receive the original bearer token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.userInfos++
		json.NewEncoder(w).Encode(map[string]any{"sub": subject, "email": subject + "@example.test", "roles": []string{"userinfo-user"}})
	default:
		http.NotFound(w, r)
	}
}

type oidcE2EPortal struct {
	server *httptest.Server
	client *http.Client
	base   string
	issuer *oidcE2EIssuer
}

func newOIDCE2EPortal(t *testing.T, issuer *oidcE2EIssuer, base, signer, mode string) *oidcE2EPortal {
	t.Helper()
	logger := zap.NewNop()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	providerConfig := &oauth.Config{Name: "upstream", Realm: "upstream", Driver: "generic", ClientID: oidcE2EClientID, ClientSecret: oidcE2EClientSecret, BaseAuthURL: issuer.server.URL, MetadataURL: issuer.server.URL + "/.well-known/openid-configuration", TLSInsecureSkipVerify: true}
	// The self-signed upstream certificate is confined to this local fixture.
	// No nonce, PKCE, or JWT signature control is disabled.
	static := mode == "static" || mode == "static-pkcs1"
	if static || mode == "combined" {
		public, id := issuer.private.Public(), issuer.keyID
		if issuer.algorithm == "RS256" {
			public, id = issuer.rsaPrivate.Public(), "upstream-rsa"
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
		if mode == "static-pkcs1" {
			block.Type = "RSA PUBLIC KEY"
			block.Bytes = x509.MarshalPKCS1PublicKey(&issuer.rsaPrivate.PublicKey)
		}
		path := filepath.Join(t.TempDir(), "upstream-public.pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		providerConfig.JwksKeys = map[string]string{id: path}
		providerConfig.AuthorizationURL = issuer.server.URL + "/authorize"
		providerConfig.TokenURL = issuer.server.URL + "/token"
		if static {
			providerConfig.MetadataURL = ""
			providerConfig.Issuer = issuer.server.URL
		}
	}
	if issuer.accessMode == "jwt" {
		providerConfig.AccessTokenAudience = "resource-api"
	}
	if issuer.accessMode == "userinfo" {
		providerConfig.UserInfoFields = []string{"email", "roles"}
	}
	var params map[string]any
	if err := json.Unmarshal(oidcE2EJSON(t, providerConfig), &params); err != nil {
		t.Fatal(err)
	}
	delete(params, "name")
	provider, err := idp.NewIdentityProvider(&idp.IdentityProviderConfig{Name: "upstream", Kind: "oauth", Params: params}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.(*oauth.IdentityProvider).Close)
	if err := provider.Configure(); err != nil {
		t.Fatal("configure OAuth provider", err)
	}
	db := newJWKSE2EDatabase(t)
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{"path": db, "realm": "local"}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal("configure local fixture store", err)
	}
	keys := []string{"crypto default autogenerate tag " + t.Name(), "crypto default token lifetime 1234", "crypto default token name oauth_portal_token"}
	switch signer {
	case "HS512":
		keys = append(keys, "crypto key portal-hmac sign-verify "+oidcE2EPortalSecret)
	case "RS512":
		keys = append(keys, e2eRSAKey)
	case "ES256":
		keys = append(keys, e2eECKey)
	case "EdDSA", "Ed25519":
		keys = append(keys, "crypto default autogenerate algorithm "+signer)
	case "ordered HMAC":
		keys = append(keys, "crypto key portal-hmac sign-verify "+oidcE2EPortalSecret, e2eRSAKey)
	}
	cookies := cookie.NewConfig()
	cookies.AccessTokenCookieName = "oauth_portal_token"
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "oauth-e2e", IdentityStores: []string{"local"}, IdentityProviders: []string{"upstream"}, RawCryptoKeyStoreConfig: keys, CookieConfig: cookies}, Logger: logger, IdentityStores: []ids.IdentityStore{store}, IdentityProviders: []idp.IdentityProvider{provider}})
	if err != nil {
		t.Fatal("construct OAuth E2E portal", err)
	}
	t.Cleanup(portal.Close)
	gatekeeper, err := authz.NewGatekeeper(&authz.PolicyConfig{Name: "oauth-e2e", AuthURLPath: base + "/login", ValidateBearerHeader: true, RawCryptoKeyStoreConfig: keys, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer editor userinfo-user"}, Action: "allow stop"}}}, logger)
	if err != nil {
		t.Fatal("construct OAuth E2E gatekeeper", err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protected" {
			ar := requests.NewAuthorizationRequest()
			err := gatekeeper.Authenticate(w, r, ar)
			if ar.Response.Authorized {
				if err != nil {
					t.Error("gatekeeper returned an error with authorized access")
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("protected-resource"))
			}
			// With redirects enabled, Authenticate writes the denial response
			// and also returns the validation error to its embedding handler.
			return
		}
		if base != "" && !strings.HasPrefix(r.URL.Path, base+"/") {
			http.NotFound(w, r)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("portal execution failed")
		}
	})
	server.StartTLS()
	// Drain HTTP requests before releasing portal and provider workers. The
	// earlier cleanup also covers construction failures before the listener starts.
	t.Cleanup(server.Close)
	issuer.mu.Lock()
	issuer.callback = server.URL + base + "/oauth2/upstream/authorization-code-callback"
	issuer.mu.Unlock()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	pool.AddCert(issuer.server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &oidcE2EPortal{server: server, client: client, base: base, issuer: issuer}
}

func (p *oidcE2EPortal) login(t *testing.T, want int) (string, http.Header) {
	t.Helper()
	client := *p.client
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	location := p.server.URL + p.base + "/oauth2/upstream"
	for step := 0; step < 3; step++ {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("OAuth journey request failed")
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if step < 2 {
			if resp.StatusCode != 302 {
				t.Fatalf("OAuth redirect step %d returned HTTP %d", step, resp.StatusCode)
			}
			location = resp.Header.Get("Location")
			continue
		}
		if resp.StatusCode != want {
			t.Fatalf("OAuth callback returned HTTP %d, want %d", resp.StatusCode, want)
		}
		token := strings.TrimPrefix(resp.Header.Get("Authorization"), "Bearer ")
		if want != http.StatusSeeOther {
			if token != "" {
				t.Fatal("failed login issued portal token")
			}
			for _, c := range resp.Cookies() {
				if c.Name == "oauth_portal_token" && c.Value != "" && c.MaxAge >= 0 {
					t.Fatal("failed login issued authenticated cookie")
				}
			}
		}
		return token, resp.Header
	}
	t.Fatal("OAuth journey did not complete")
	return "", nil
}

func (p *oidcE2EPortal) get(t *testing.T, path, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, p.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal("consumer request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestE2EOAuthEd25519PortalSigning(t *testing.T) {
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		for _, signer := range []string{"default", "HS512", "RS512", "ES256", "EdDSA", "Ed25519", "ordered HMAC"} {
			t.Run(alg+"/"+signer, func(t *testing.T) {
				issuer := newOIDCE2EIssuer(t, alg, "opaque", "", true)
				p := newOIDCE2EPortal(t, issuer, "/tenant/auth", signer, "discovery")
				token, headers := p.login(t, 303)
				if token == "" {
					t.Fatal("no portal credential")
				}
				issuer.mu.Lock()
				subject, upstream := issuer.lastSubject, issuer.lastIdentity
				exchanges, metadata, keys := issuer.exchanges, issuer.metadataFetches, issuer.keyFetches
				issuer.mu.Unlock()
				if exchanges != 1 || metadata != 1 || keys != 1 {
					t.Fatal("discovery/code exchange was not exercised")
				}
				wantAlg := signer
				if signer == "default" {
					wantAlg = "ES512"
				}
				if signer == "ordered HMAC" {
					wantAlg = "HS512"
				}
				status, discovery := p.get(t, p.base+e2eJWKSPath, "")
				var verified *jwtlib.Token
				if wantAlg == "HS512" {
					if status != 404 {
						t.Fatal("symmetric signer unexpectedly published JWKS")
					}
					var err error
					verified, err = jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return []byte(oidcE2EPortalSecret), nil }, jwtlib.WithValidMethods([]string{wantAlg}), jwtlib.WithExpirationRequired())
					if err != nil {
						t.Fatal("independent HMAC verification failed")
					}
				} else {
					if status != 200 {
						t.Fatal("portal signing discovery unavailable")
					}
					var document struct {
						Keys []map[string]string `json:"keys"`
					}
					if err := json.Unmarshal(discovery, &document); err != nil {
						t.Fatal(err)
					}
					verified = verifyE2EJWKSToken(t, document.Keys, token, subject)
					for _, key := range document.Keys {
						if strings.HasPrefix(key["kid"], "upstream-") {
							t.Fatal("upstream key leaked into portal key store")
						}
					}
				}
				if verified.Method.Alg() != wantAlg {
					t.Fatal("upstream algorithm changed portal signer")
				}
				claims := verified.Claims.(jwtlib.MapClaims)
				if claims["exp"].(float64)-claims["iat"].(float64) != 1234 {
					t.Fatal("portal token lifetime changed")
				}
				found := false
				response := &http.Response{Header: headers}
				for _, c := range response.Cookies() {
					if c.Name == "oauth_portal_token" && c.Value == token {
						found = true
						if !c.Secure || !c.HttpOnly {
							t.Fatal("portal cookie lost protections")
						}
					}
				}
				if !found {
					t.Fatal("configured token cookie name changed")
				}
				if status, body := p.get(t, "/protected", token); status != 200 || string(body) != "protected-resource" {
					t.Fatal("portal credential did not authorize")
				}
				if status, _ := p.get(t, "/protected", upstream); status == 200 {
					t.Fatal("upstream token authorized against portal trust")
				}
			})
		}
	}
}

func TestE2EOAuthEd25519SourcesAndClaims(t *testing.T) {
	for _, tc := range []struct {
		name, alg, access, mode, base string
		mixed                         bool
	}{
		{"EdDSA static", "EdDSA", "opaque", "static", "", false},
		{"Ed25519 static", "Ed25519", "opaque", "static", "/auth", false},
		{"RSA static", "RS256", "opaque", "static", "/auth", false},
		{"RSA PKCS1 static", "RS256", "opaque", "static-pkcs1", "/auth", false},
		{"combined sources", "Ed25519", "opaque", "combined", "/auth", true},
		{"Ed-only JWKS", "EdDSA", "opaque", "discovery", "", false},
		{"verified access claims", "EdDSA", "jwt", "discovery", "/auth", true},
		{"RSA identity Ed access", "RS256", "jwt", "discovery", "/auth", true},
		{"opaque UserInfo", "Ed25519", "userinfo", "discovery", "/auth", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newOIDCE2EIssuer(t, tc.alg, tc.access, "", tc.mixed)
			p := newOIDCE2EPortal(t, issuer, tc.base, "HS512", tc.mode)
			token, _ := p.login(t, 303)
			parsed, err := jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return []byte(oidcE2EPortalSecret), nil }, jwtlib.WithValidMethods([]string{"HS512"}))
			if err != nil {
				t.Fatal("portal verification failed")
			}
			roles := parsed.Claims.(jwtlib.MapClaims)["roles"].([]any)
			want := "viewer"
			if tc.access == "jwt" {
				want = "editor"
			}
			if tc.access == "userinfo" {
				want = "userinfo-user"
			}
			found := false
			for _, role := range roles {
				found = found || role == want
			}
			if !found {
				t.Fatal("expected upstream roles were not carried through verified flow")
			}
			issuer.mu.Lock()
			fetches, metadata, userInfos := issuer.keyFetches, issuer.metadataFetches, issuer.userInfos
			issuer.mu.Unlock()
			if strings.HasPrefix(tc.mode, "static") && (fetches != 0 || metadata != 0) {
				t.Fatal("static configuration fetched discovery")
			}
			if tc.access == "userinfo" && userInfos != 1 {
				t.Fatal("UserInfo interaction missing")
			}
			if status, _ := p.get(t, "/protected", token); status != 200 {
				t.Fatal("OAuth credential did not authorize")
			}
		})
	}
}

func TestE2EOAuthEd25519RejectsInvalidIdentity(t *testing.T) {
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		for _, failure := range []string{"signature", "issuer", "audience", "nonce", "nonce type", "expired", "unknown kid", "state"} {
			t.Run(alg+"/"+failure, func(t *testing.T) {
				issuer := newOIDCE2EIssuer(t, alg, "opaque", failure, true)
				p := newOIDCE2EPortal(t, issuer, "/auth", "HS512", "discovery")
				p.login(t, 401)
				if status, _ := p.get(t, "/protected", ""); status == 200 {
					t.Fatal("failed login granted protected access")
				}
			})
		}
	}
}

func TestE2EOAuthEd25519Rotation(t *testing.T) {
	issuer := newOIDCE2EIssuer(t, "EdDSA", "opaque", "", true)
	p := newOIDCE2EPortal(t, issuer, "/auth", "ES256", "discovery")
	first, _ := p.login(t, 303)
	for _, sameID := range []bool{false, true} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		issuer.mu.Lock()
		issuer.private = private
		issuer.algorithm = "Ed25519"
		if !sameID {
			issuer.keyID = "upstream-next"
		}
		issuer.keys = []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": issuer.keyID, "x": base64.RawURLEncoding.EncodeToString(public)}}
		issuer.mu.Unlock()
		token, _ := p.login(t, 303)
		if status, _ := p.get(t, "/protected", token); status != 200 {
			t.Fatal("rotated upstream credential failed")
		}
	}
	issuer.mu.Lock()
	fetches := issuer.keyFetches
	issuer.mu.Unlock()
	if fetches != 3 {
		t.Fatalf("rotation fetched JWKS %d times, want 3", fetches)
	}
	if status, _ := p.get(t, "/protected", first); status != 200 {
		t.Fatal("upstream rotation changed existing portal session validity")
	}
}

func TestE2EOAuthEd25519MissingKeyIDs(t *testing.T) {
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		t.Run(alg, func(t *testing.T) {
			issuer := newOIDCE2EIssuer(t, alg, "opaque", "missing kid", true)
			issuer.mu.Lock()
			for _, key := range issuer.keys {
				delete(key, "kid")
			}
			issuer.mu.Unlock()
			p := newOIDCE2EPortal(t, issuer, "/auth", "HS512", "discovery")
			token, _ := p.login(t, 303)
			if status, body := p.get(t, "/protected", token); status != 200 || string(body) != "protected-resource" {
				t.Fatal("compatible key selection did not complete login")
			}
		})
	}
}
