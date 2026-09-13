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

package oidc_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

// This host has its own authentication and identity implementation. It imports
// only the public oidc package, never authn or the portal's private state.
type standaloneIdentityVerifier struct {
	mu       sync.Mutex
	disabled bool
}

func (v *standaloneIdentityVerifier) WithIdentity(ctx context.Context, proof oidc.Authentication, apply func(oidc.Identity) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.disabled || proof.Backend != "staff-directory" || proof.Realm != "employees" || proof.Username != "alice" || proof.Evidence.UserID != "immutable-alice" || proof.Evidence.CredentialVersion != 1 || proof.Evidence.BackendVersion != "v1" {
		return oidc.ErrIdentityDenied
	}
	return apply(oidc.Identity{Username: "alice", Name: "Alice", Email: "alice@example.test", EmailVerified: true})
}

func (v *standaloneIdentityVerifier) authenticate(username, password string) (oidc.Authentication, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.disabled || username != "alice" || password != "standalone-test-password" {
		return oidc.Authentication{}, oidc.ErrIdentityDenied
	}
	proof := oidc.Authentication{Realm: "employees", Backend: "staff-directory", Username: "alice", Methods: []string{"pwd"}}
	proof.Evidence.UserID = "immutable-alice"
	proof.Evidence.BackendVersion = "v1"
	proof.Evidence.CredentialVersion = 1
	proof.Evidence.AuthenticatedAt = time.Now().Unix()
	proof.Evidence.Method = "password"
	return proof, nil
}

type standaloneResponse struct {
	status int
	header http.Header
	body   []byte
}

func TestE2EStandaloneProvider(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "oidc.pem")
	if err := oidc.GenerateSigningKeyFile(keyFile); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ mount, method string }{
		{"", "none"}, {"/api/identity", "none"},
		{"", "client_secret_basic"}, {"/api/identity", "client_secret_basic"},
		{"", "client_secret_post"}, {"/api/identity", "client_secret_post"},
	} {
		t.Run(tc.method+tc.mount, func(t *testing.T) {
			mount := tc.mount
			server := httptest.NewUnstartedServer(nil)
			t.Cleanup(server.Close)
			origin := "https://" + server.Listener.Addr().String()
			issuer := origin + mount
			verifier := &standaloneIdentityVerifier{}
			registration, err := oidcparser.NewOIDCClientConfigFromDirectives("Standalone application", []string{
				"token_endpoint_auth_method " + tc.method,
				"redirect_uris https://rp.example.test/callback",
				"scopes openid profile email",
			})
			if err != nil {
				t.Fatal(err)
			}
			config := oidc.Config{Enabled: true, Issuer: issuer, Realms: []string{"employees"}, SigningKeyFiles: []string{keyFile}}
			if err := config.AddClient(registration); err != nil {
				t.Fatal(err)
			}
			configFile := filepath.Join(t.TempDir(), "provider.json")
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal("cannot encode provisioned configuration")
			}
			if err := os.WriteFile(configFile, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			loadProvider := func() *oidc.Provider {
				t.Helper()
				data, err := os.ReadFile(configFile)
				if err != nil {
					t.Fatal(err)
				}
				var restored oidc.Config
				if json.Unmarshal(data, &restored) != nil {
					t.Fatal("cannot restore provisioned configuration")
				}
				provider, err := oidc.NewProvider(&restored, verifier, oidc.Options{SessionCookieName: "APP_SESSION", RequestCookieName: "APP_REQUEST", LoginURL: issuer + "/sign-in?fresh=1"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(provider.Close)
				return provider
			}
			concrete := loadProvider()
			var provider oidc.OpenIDProvider = concrete
			var current atomic.Pointer[oidc.Provider]
			current.Store(concrete)
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				provider := current.Load()
				switch r.URL.Path {
				case mount + "/sign-in", mount + "/sign-out", mount + "/fresh":
					if r.Method != http.MethodPost {
						w.WriteHeader(http.StatusMethodNotAllowed)
						return
					}
					if !provider.ValidateLoginRequest(w, r) {
						return
					}
					switch r.URL.Path {
					case mount + "/sign-out":
						provider.Logout(w, r)
						w.WriteHeader(http.StatusNoContent)
					case mount + "/fresh":
						provider.ClearSession(w, r)
						w.WriteHeader(http.StatusNoContent)
					default:
						r.Body = http.MaxBytesReader(w, r.Body, 4096)
						if err := r.ParseForm(); err != nil {
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						proof, err := verifier.authenticate(r.PostForm.Get("username"), r.PostForm.Get("password"))
						if err != nil {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						if err := provider.CompleteLogin(r.Context(), w, r, proof); err != nil {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						w.WriteHeader(http.StatusSeeOther)
					}
				default:
					provider.ServeHTTP(w, r)
				}
			})
			server.StartTLS()
			client := server.Client()
			client.Timeout = 10 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client.Jar, _ = cookiejar.New(nil)
			request := func(method, path string, form url.Values, headers http.Header) standaloneResponse {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), method, issuer+path, strings.NewReader(form.Encode()))
				if err != nil {
					t.Fatal(err)
				}
				if method == "POST" {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				for key, values := range headers {
					for _, value := range values {
						r.Header.Add(key, value)
					}
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal("standalone HTTP request failed")
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				if err != nil {
					t.Fatal("standalone response read failed")
				}
				return standaloneResponse{status: response.StatusCode, header: response.Header, body: body}
			}
			expect := func(response standaloneResponse, status int) {
				t.Helper()
				if response.status != status {
					t.Fatalf("HTTP status=%d, want %d", response.status, status)
				}
			}
			metadata := request("GET", "/.well-known/openid-configuration", nil, nil)
			expect(metadata, http.StatusOK)
			var discovery map[string]any
			if json.Unmarshal(metadata.body, &discovery) != nil || discovery["issuer"] != issuer || discovery["jwks_uri"] != issuer+"/oidc/jwks" {
				t.Fatal("invalid standalone discovery")
			}
			if !provider.SupportsRealm("employees") || provider.SupportsRealm("local") {
				t.Fatal("realm interface ignored configuration")
			}
			headers := http.Header{"Origin": {origin}}
			expect(request("POST", "/sign-in", url.Values{"username": {"alice"}, "password": {"wrong"}}, headers), http.StatusUnauthorized)
			expect(request("POST", "/sign-in", nil, http.Header{"Origin": {"https://other.test"}}), http.StatusForbidden)
			const verifierValue = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
			challenge := sha256.Sum256([]byte(verifierValue))
			parameters := url.Values{"client_id": {registration.ClientID}, "redirect_uri": {"https://rp.example.test/callback"}, "response_type": {"code"}, "scope": {"openid profile email"}, "nonce": {"standalone-nonce"}, "state": {"standalone-state"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
			authenticate := func(fresh bool) map[string]any {
				t.Helper()
				if fresh {
					parameters.Set("prompt", "login")
				}
				start := request("GET", "/oidc/authorize?"+parameters.Encode(), nil, nil)
				expect(start, http.StatusSeeOther)
				if start.header.Get("Location") != issuer+"/sign-in?fresh=1" {
					t.Fatal("custom login URL ignored")
				}
				if fresh {
					expect(request("POST", "/fresh", nil, headers), http.StatusNoContent)
				}
				login := request("POST", "/sign-in", url.Values{"username": {"alice"}, "password": {"standalone-test-password"}}, headers)
				expect(login, http.StatusSeeOther)
				if login.header.Get("Location") != issuer+"/oidc/continue" {
					t.Fatal("login lost pending authorization")
				}
				consent := request("GET", "/oidc/continue", nil, nil)
				expect(consent, http.StatusOK)
				match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(consent.body)
				if len(match) != 2 {
					t.Fatal("missing standalone consent form")
				}
				approved := request("POST", "/oidc/continue", url.Values{"csrf": {html.UnescapeString(string(match[1]))}, "decision": {"allow"}}, headers)
				expect(approved, http.StatusFound)
				callback, err := url.Parse(approved.header.Get("Location"))
				if err != nil || callback.Query().Get("code") == "" || callback.Query().Get("state") != "standalone-state" {
					t.Fatal("standalone code callback invalid")
				}
				form := url.Values{"grant_type": {"authorization_code"}, "client_id": {registration.ClientID}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://rp.example.test/callback"}}
				tokenHeaders := make(http.Header)
				setSecret := func(secret string) {
					switch registration.TokenEndpointAuthMethod {
					case "client_secret_basic":
						tokenHeaders.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(registration.ClientID)+":"+url.QueryEscape(secret))))
					case "client_secret_post":
						form.Set("client_secret", secret)
					}
				}
				if registration.TokenEndpointAuthMethod != "none" {
					setSecret("incorrect-secret")
					expect(request("POST", "/oidc/token", form, tokenHeaders), http.StatusUnauthorized)
					setSecret(registration.ClientSecret)
				}
				expect(request("POST", "/oidc/token", form, tokenHeaders), http.StatusBadRequest)
				form.Set("code_verifier", verifierValue)
				response := request("POST", "/oidc/token", form, tokenHeaders)
				expect(response, http.StatusOK)
				var tokens map[string]any
				if json.Unmarshal(response.body, &tokens) != nil || tokens["access_token"] == nil || tokens["id_token"] == nil {
					t.Fatal("missing standalone tokens")
				}
				return tokens
			}
			tokens := authenticate(false)
			jwks := request("GET", "/oidc/jwks", nil, nil)
			expect(jwks, http.StatusOK)
			claims := verifyStandaloneIDToken(t, tokens["id_token"].(string), jwks.body, issuer, registration.ClientID)
			userinfo := func(tokens map[string]any) standaloneResponse {
				t.Helper()
				return request("GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
			}
			info := userinfo(tokens)
			expect(info, http.StatusOK)
			var identity map[string]any
			if json.Unmarshal(info.body, &identity) != nil || identity["sub"] != claims["sub"] || identity["email_verified"] != true || identity["preferred_username"] != "alice" {
				t.Fatal("verifier identity was not used for UserInfo")
			}
			replacement := authenticate(true)
			expect(userinfo(tokens), http.StatusUnauthorized)
			expect(userinfo(replacement), http.StatusOK)
			verifier.mu.Lock()
			verifier.disabled = true
			verifier.mu.Unlock()
			expect(userinfo(replacement), http.StatusUnauthorized)
			verifier.mu.Lock()
			verifier.disabled = false
			verifier.mu.Unlock()
			expect(request("POST", "/sign-out", nil, headers), http.StatusNoContent)
			target, _ := url.Parse(issuer + "/oidc/continue")
			for _, c := range client.Jar.Cookies(target) {
				if c.Name == "APP_SESSION" || c.Name == "APP_REQUEST" {
					t.Fatal("logout retained standalone cookies")
				}
			}
			expect(userinfo(replacement), http.StatusUnauthorized)
			parameters.Set("prompt", "none")
			silent := request("GET", "/oidc/authorize?"+parameters.Encode(), nil, nil)
			expect(silent, http.StatusFound)
			target, _ = url.Parse(silent.header.Get("Location"))
			if target.Query().Get("error") != "login_required" {
				t.Fatal("logout retained standalone session")
			}
			provider.Close()
			expect(request("GET", "/.well-known/openid-configuration", nil, nil), http.StatusServiceUnavailable)
			// Restart from the same persisted configuration and key. The original
			// relying party credentials and published signing key must still work.
			restored := loadProvider()
			current.Store(restored)
			parameters.Del("prompt")
			restoredTokens := authenticate(false)
			expect(userinfo(restoredTokens), http.StatusOK)
			restoredJWKS, err := json.Marshal(restored.JWKS())
			if err != nil {
				t.Fatal("cannot encode restored signing keys")
			}
			verifyStandaloneIDToken(t, tokens["id_token"].(string), restoredJWKS, issuer, registration.ClientID)
			verifyStandaloneIDToken(t, restoredTokens["id_token"].(string), jwks.body, issuer, registration.ClientID)
		})
	}
}

func verifyStandaloneIDToken(t *testing.T, raw string, jwks []byte, issuer, clientID string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("invalid ID token structure")
	}
	decode := func(part string) []byte {
		t.Helper()
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal("invalid token encoding")
		}
		return data
	}
	var header map[string]any
	var claims map[string]any
	var keys struct {
		Keys []map[string]string `json:"keys"`
	}
	if json.Unmarshal(decode(parts[0]), &header) != nil || json.Unmarshal(decode(parts[1]), &claims) != nil || json.Unmarshal(jwks, &keys) != nil {
		t.Fatal("invalid ID token or JWKS JSON")
	}
	if header["alg"] != "RS256" || len(keys.Keys) != 1 || header["kid"] != keys.Keys[0]["kid"] {
		t.Fatal("unexpected ID-token signing key")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(decode(keys.Keys[0]["n"])), E: int(new(big.Int).SetBytes(decode(keys.Keys[0]["e"])).Int64())}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], decode(parts[2])) != nil {
		t.Fatal("invalid ID-token signature")
	}
	subject, _ := claims["sub"].(string)
	if claims["iss"] != issuer || claims["aud"] != clientID || claims["nonce"] != "standalone-nonce" || subject == "" || subject == "alice" || claims["exp"].(float64) <= float64(time.Now().Unix()) {
		t.Fatal("invalid ID-token claims")
	}
	return claims
}
