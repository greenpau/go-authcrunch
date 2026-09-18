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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const loginIdentityTOTPSecret = "0123456789abcdef0123456789abcdef"

// Reuse the public HTTP and independent JWT-verification helpers. This fixture
// varies login policy without exposing the portal or its sandbox/session state.
func newLoginIdentityE2E(t *testing.T, refresh, provider, mfa bool, subject string, cookieConfigs ...*cookie.Config) (*oidcE2EFixture, *local.IdentityStore, string) {
	t.Helper()
	return newLoginIdentityConfiguredE2E(t, refresh, provider, mfa, subject, nil, cookieConfigs...)
}

func newLoginIdentityConfiguredE2E(t *testing.T, refresh, provider, mfa bool, subject string, configure func(*authn.PortalConfig), cookieConfigs ...*cookie.Config) (*oidcE2EFixture, *local.IdentityStore, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		password := tests.TestPwd1Hash(t)
		if name == "bob" {
			password = tests.TestPwd2Hash(t)
		}
		if err := db.AddUser(&requests.Request{User: requests.User{Username: name, Email: name + "@example.test", Password: password, Roles: []string{"authp/user", name}}}); err != nil {
			t.Fatal("could not provision login identity")
		}
	}
	if mfa {
		if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "login identity test", Secret: loginIdentityTOTPSecret, Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true}}); err != nil {
			t.Fatal("could not provision login factor")
		}
	}
	var stores []ids.IdentityStore
	for _, realm := range []string{"local", "excluded"} {
		store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: realm, Kind: "local", Params: map[string]any{"path": dbPath, "realm": realm}}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Configure(); err != nil {
			t.Fatal(err)
		}
		stores = append(stores, store)
	}
	origin := "https://" + server.Listener.Addr().String()
	cfg := &authn.PortalConfig{
		Name: "login-identity", IdentityStores: []string{"local", "excluded"}, CookieConfig: cookie.NewConfig(),
		API: &authn.APIConfig{ProfileEnabled: true}, RawCryptoKeyStoreConfig: []string{e2eRSAKey},
	}
	if len(cookieConfigs) != 0 {
		if err := cfg.ConfigureCookies(cookieConfigs[0]); err != nil {
			t.Fatal(err)
		}
	}
	actions := []string{"overwrite email alias@example.test"}
	if subject != "" {
		actions = append(actions, "overwrite sub "+subject)
	}
	cfg.UserTransformerConfigs = []*transformer.Config{{Matchers: []string{"exact match sub alice"}, Actions: actions}}
	if refresh {
		cfg.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: origin, BasePath: "/auth", BodyTransportEnabled: true}
	}
	callback := "https://rp.example.test/callback?registered=yes"
	if provider {
		cfg.OIDCProvider = &oidc.Config{Enabled: true, Issuer: origin + "/auth", Realms: []string{"local"}, SigningKeyFiles: []string{"../../testdata/rskeys/test_1_pri.pem"}, Clients: []*oidc.ClientConfig{{ClientID: "second", ClientSecret: oidcE2ESecret, RedirectURIs: []string{callback}, SkipConsent: true, RequirePKCE: true}}}
	}
	if configure != nil {
		configure(cfg)
	}
	portal, err := authn.NewPortal(authn.PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: stores})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("login identity request failed")
		}
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &oidcE2EFixture{server: server, client: client, issuer: origin + "/auth", callback: callback}
	f.close = func() { server.Close(); portal.Close() }
	t.Cleanup(f.close)
	rr := &requests.Request{User: requests.User{Username: "alice"}}
	if err := stores[0].Request(operator.IdentifyUser, rr); err != nil || rr.Authentication.UserID == "" {
		t.Fatal("could not identify provisioned account")
	}
	return f, stores[0].(*local.IdentityStore), rr.Authentication.UserID
}

func loginIdentityTOTP() string {
	return loginIdentityTOTPAt(time.Now())
}

func loginIdentityTOTPAt(at time.Time) string {
	mac := hmac.New(sha1.New, []byte(loginIdentityTOTPSecret))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
}

func loginIdentityResponse(t *testing.T, response oidcE2EResponse) apiauth.AuthResponse {
	t.Helper()
	oidcE2EStatus(t, response, http.StatusOK)
	var body apiauth.AuthResponse
	if err := json.Unmarshal(response.body, &body); err != nil {
		t.Fatal("malformed login response")
	}
	return body
}

func loginIdentityCookie(f *oidcE2EFixture, name string) string {
	u, _ := url.Parse(f.issuer + "/portal")
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func loginIdentityClaims(t *testing.T, f *oidcE2EFixture, token, subject string) jwtlib.MapClaims {
	t.Helper()
	response := f.request(t, http.MethodGet, e2eJWKSPath, nil, nil)
	oidcE2EStatus(t, response, http.StatusOK)
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(response.body, &jwks); err != nil {
		t.Fatal("malformed portal JWKS")
	}
	return verifyE2EJWKSToken(t, jwks.Keys, token, subject).Claims.(jwtlib.MapClaims)
}

func TestE2ELoginIdentityTransform(t *testing.T) {
	for _, features := range []struct {
		name                    string
		refresh, oidc, excluded bool
	}{
		{name: "access only"},
		{name: "refresh", refresh: true},
		{name: "oidc", oidc: true},
		{name: "both", refresh: true, oidc: true},
		{name: "excluded realm", refresh: true, oidc: true, excluded: true},
	} {
		for _, flow := range []string{"html", "json"} {
			for _, mfa := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/mfa=%t", features.name, flow, mfa), func(t *testing.T) {
					f, _, id := newLoginIdentityE2E(t, features.refresh, features.oidc, mfa, "")
					realm := "local"
					if features.excluded {
						realm = "excluded"
					}
					origin := http.Header{"Origin": {f.server.URL}}
					var token string
					if flow == "html" {
						// Email aliases and case canonicalization must retain the
						// same backend account through the entire sandbox.
						start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"ALICE@EXAMPLE.TEST"}, "realm": {realm}}, origin)
						oidcE2EStatus(t, start, http.StatusSeeOther)
						sandbox := start.header.Get("Location")
						oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
						if mfa {
							oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {loginIdentityTOTP()}}, origin), http.StatusSeeOther)
						}
						oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
						token = loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
						// Completed proof is single use, including after a valid
						// access cookie was obtained.
						replayed := f.request(t, http.MethodGet, sandbox, nil, nil)
						if replayed.header.Get("Authorization") != "" {
							t.Fatal("redeemed sandbox issued another credential")
						}
					} else {
						req := apiauth.AuthRequest{Username: "ALICE", Realm: realm}
						start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
						req.Username = "alice@example.test"
						req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
						req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd1
						result := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
						if mfa {
							if result.Authenticated || result.NextChallenge == "" {
								t.Fatal("password bypassed MFA")
							}
							req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
							req.ChallengeKind, req.ChallengeResponse = result.NextChallenge, loginIdentityTOTP()
							result = loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
						}
						if !result.Authenticated {
							t.Fatal("completed checkpoints did not authenticate")
						}
						token = result.AccessToken
						if features.refresh && !features.excluded {
							if result.AccessToken != "" || result.RefreshToken != "" {
								t.Fatal("browser JSON disclosed credentials")
							}
							token = loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
						}
						if replay := f.jsonRequest(t, "/login", req, "", origin); replay.status == http.StatusOK {
							t.Fatal("redeemed JSON proof was accepted again")
						}
					}
					claims := loginIdentityClaims(t, f, token, "alice")
					if claims["email"] != "alias@example.test" || claims["origin"] != realm {
						t.Fatal("signed token lost transformed email or canonical realm")
					}
					who := f.request(t, http.MethodGet, "/whoami", nil, http.Header{"Authorization": {"Bearer " + token}})
					oidcE2EStatus(t, who, http.StatusOK)
					if features.refresh && !features.excluded {
						rotation := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}})
						oidcE2EStatus(t, rotation, http.StatusOK)
						renewed := loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice")
						if renewed["email"] != "alias@example.test" || renewed["sid"] != claims["sid"] {
							t.Fatal("refresh changed identity or lost transformation")
						}
					} else if loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") != "" {
						t.Fatal("access-only login created a refresh family")
					}
					if features.oidc && !features.excluded {
						code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
						tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
						idClaims := f.verifyIDToken(t, tokens, "second")
						binding, _ := json.Marshal([]string{"local", "local", id})
						digest := sha256.Sum256(binding)
						if idClaims["sub"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
							t.Fatal("OIDC subject did not identify original immutable account")
						}
						info := f.request(t, http.MethodGet, "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
						oidcE2EStatus(t, info, http.StatusOK)
						var body map[string]any
						if json.Unmarshal(info.body, &body) != nil || body["email"] != "alice@example.test" || body["sub"] != idClaims["sub"] {
							t.Fatal("OIDC UserInfo did not retain backend identity")
						}
					} else if loginIdentityCookie(f, "AUTHP_OIDC_SESSION_ID") != "" {
						t.Fatal("excluded login created an OIDC session")
					}
				})
			}
		}
	}
}

func TestE2ELoginIdentityMutation(t *testing.T) {
	for _, feature := range []string{"access only", "refresh", "oidc"} {
		for _, flow := range []string{"html", "json"} {
			t.Run(feature+"/"+flow, func(t *testing.T) {
				f, store, id := newLoginIdentityE2E(t, feature == "refresh", feature == "oidc", true, "")
				origin := http.Header{"Origin": {f.server.URL}}
				var sandbox string
				var req apiauth.AuthRequest
				if flow == "html" {
					start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
					oidcE2EStatus(t, start, http.StatusSeeOther)
					sandbox = start.header.Get("Location")
					oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
				} else {
					req = apiauth.AuthRequest{Username: "alice", Realm: "local"}
					start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
					req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
					req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd1
					factor := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
					if factor.Authenticated || factor.NextChallenge == "" {
						t.Fatal("password bypassed MFA")
					}
					req.SandboxID, req.SandboxSecret = factor.SandboxID, factor.SandboxSecret
					req.ChallengeKind, req.ChallengeResponse = factor.NextChallenge, loginIdentityTOTP()
				}
				// Invalidate the captured version through the public backend API
				// while the actual client is between password and MFA completion.
				if err := store.RevokeUserSessions(t.Context(), id); err != nil {
					t.Fatal(err)
				}
				if flow == "html" {
					factor := f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {loginIdentityTOTP()}}, origin)
					if factor.status != http.StatusUnauthorized && factor.status != http.StatusForbidden && factor.status != http.StatusSeeOther {
						t.Fatalf("unexpected checkpoint status %d", factor.status)
					}
					final := f.request(t, http.MethodGet, sandbox, nil, nil)
					if final.header.Get("Authorization") != "" || final.status == http.StatusSeeOther {
						t.Fatal("changed backend identity completed HTML login")
					}
				} else {
					denied := f.jsonRequest(t, "/login", req, "", origin)
					oidcE2EStatus(t, denied, http.StatusUnauthorized)
					var result apiauth.AuthResponse
					if json.Unmarshal(denied.body, &result) != nil || result.Authenticated || result.AccessToken != "" || result.RefreshToken != "" {
						t.Fatal("changed backend identity obtained JSON credentials")
					}
				}
				for _, name := range []string{"AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"} {
					if loginIdentityCookie(f, name) != "" {
						t.Fatal("changed backend identity obtained a credential cookie")
					}
				}
			})
		}
	}
}

func TestE2ELoginIdentitySubjectCannotSelectAccount(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		for _, flow := range []string{"html", "json"} {
			t.Run(fmt.Sprintf("refresh=%t/%s", refresh, flow), func(t *testing.T) {
				f, _, _ := newLoginIdentityE2E(t, refresh, true, false, "bob")
				origin := http.Header{"Origin": {f.server.URL}}
				var token string
				if flow == "html" {
					start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
					oidcE2EStatus(t, start, http.StatusSeeOther)
					sandbox := start.header.Get("Location")
					wrong := f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd2}}, origin)
					if wrong.status == http.StatusSeeOther || wrong.header.Get("Authorization") != "" {
						t.Fatal("transformed subject's password completed the original account's checkpoint")
					}
					oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
					oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
					token = loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
				} else {
					req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
					start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
					req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
					req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd2
					oidcE2EStatus(t, f.jsonRequest(t, "/login", req, "", origin), http.StatusUnauthorized)
					req.ChallengeResponse = tests.TestPwd1
					result := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
					if !result.Authenticated {
						t.Fatal("canonical account's password did not complete login")
					}
					token = result.AccessToken
					if refresh {
						token = loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
					}
				}
				subject := "bob"
				if refresh {
					subject = "alice" // Renewable access retains its canonical subject.
				}
				claims := loginIdentityClaims(t, f, token, subject)
				roles, _ := json.Marshal(claims["roles"])
				if !strings.Contains(string(roles), `"alice"`) || strings.Contains(string(roles), `"bob"`) || claims["email"] != "alias@example.test" {
					t.Fatal("claim transformation selected another backend account")
				}
				code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
				tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
				info := f.request(t, http.MethodGet, "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
				var body map[string]any
				if info.status != http.StatusOK || json.Unmarshal(info.body, &body) != nil || body["email"] != "alice@example.test" {
					t.Fatal("transformed subject selected another OIDC identity")
				}
			})
		}
	}
}
