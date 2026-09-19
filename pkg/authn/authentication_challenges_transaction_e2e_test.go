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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// Keep the real local transaction capability while arranging a committed change
// at an exact boundary in the public store protocol. No sleeps or data races.
type authenticationChallengeTransactionStore struct {
	*local.IdentityStore
	after func(operator.Type) error
}

func (s *authenticationChallengeTransactionStore) Request(op operator.Type, rr *requests.Request) error {
	if err := s.IdentityStore.Request(op, rr); err != nil {
		return err
	}
	return s.after(op)
}

func TestE2EAuthenticationChallengeDirectTransaction(t *testing.T) {
	for _, flow := range []string{"proxy basic", "HTTP basic", "proxy API key", "JSON API key", "system basic", "system API key"} {
		for _, mutation := range []string{"unchanged", "policy after identification", "policy after verification", "roles after identification", "credential revoked after verification", "account disabled after verification", "account replaced after verification"} {
			t.Run(flow+"/"+mutation, func(t *testing.T) {
				f, backend, _ := newLoginIdentityE2E(t, false, false, false, "")
				const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
				key := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "transaction regression"}}
				if err := backend.Request(operator.AddAPIKey, key); err != nil {
					t.Fatal(err)
				}
				if err := backend.Request(operator.GetAPIKeys, key); err != nil {
					t.Fatal(err)
				}
				key.Key.ID = key.Response.Payload.(*identity.APIKeyBundle).Get()[0].ID
				isKey := strings.Contains(flow, "API key")
				replacementPassword := tests.TestPwd2Hash(t)
				trigger := operator.IdentifyUser
				if strings.Contains(mutation, "verification") {
					trigger = operator.Authenticate
					if isKey {
						trigger = operator.LookupAPIKey
					}
				}
				var once sync.Once
				var changed atomic.Bool
				mutationResult := make(chan error, 1)
				store := &authenticationChallengeTransactionStore{IdentityStore: backend}
				store.after = func(op operator.Type) error {
					var mutationErr error
					if mutation == "unchanged" || op != trigger {
						return nil
					}
					once.Do(func() {
						defer func() { mutationResult <- mutationErr }()
						changed.Store(true)
						switch mutation {
						case "roles after identification":
							_, mutationErr = backend.OverwriteUserRoles("alice", "alice@example.test", []string{"authp/user", "stepup"})
							return
						case "account disabled after verification":
							mutationErr = backend.DisableUser("alice", "alice@example.test")
							return
						case "account replaced after verification":
							mutationErr = backend.DeleteUser("alice", "alice@example.test")
							if mutationErr == nil {
								_, mutationErr = backend.AddUser("alice", "alice@example.test", replacementPassword, []string{"authp/user"})
							}
							return
						}
						if strings.HasPrefix(mutation, "credential revoked") {
							if isKey {
								mutationErr = backend.Request(operator.DeleteAPIKey, key)
							} else {
								_, mutationErr = backend.ResetUserPassword("alice", "alice@example.test")
							}
							return
						}
						mutationErr = backend.Request(operator.AddMfaToken, &requests.Request{User: key.User, MfaToken: requests.MfaToken{Type: "totp", Comment: "new required factor", Secret: loginIdentityTOTPSecret, Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true}})
						if mutationErr == nil {
							_, mutationErr = backend.OverwriteUserAuthChallengeRules("alice", "alice@example.test", []string{"totp"})
						}
					})
					return mutationErr
				}
				cfg := &authn.PortalConfig{Name: "direct-transaction", IdentityStores: []string{store.GetName()}, RawCryptoKeyStoreConfig: []string{e2eRSAKey}}
				challengeSystemConfig(cfg)
				authenticationChallengeConfig(t, []string{"match role stepup", "require totp"})(cfg)
				portal, err := authn.NewPortal(authn.PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(portal.Close)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(flow, "proxy") {
						rr := &authproxy.Request{Realm: "local", Address: "198.51.100.10", Secret: r.Header.Get("X-Test-Credential")}
						var err error
						if isKey {
							err = portal.APIKeyAuth(rr)
						} else {
							err = portal.BasicAuth(rr)
						}
						if err != nil {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						io.WriteString(w, rr.Response.Payload)
						return
					}
					if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
						t.Error("portal request failed", err)
					}
				}))
				t.Cleanup(server.Close)
				client := server.Client()
				client.Timeout = 10 * time.Second
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				endpoint, method, body := "/auth/basic/login/local", http.MethodGet, ""
				if flow == "JSON API key" {
					endpoint, method, body = "/auth/login", http.MethodPost, `{"realm":"local","api_key":"`+apiKey+`"}`
				}
				req, err := http.NewRequestWithContext(t.Context(), method, server.URL+endpoint, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				basic := base64.StdEncoding.EncodeToString([]byte("alice:" + tests.TestPwd1))
				req.Header.Set("Authorization", "Basic "+basic)
				req.Header.Set("X-Test-Credential", basic)
				if isKey {
					req.Header.Set("X-Test-Credential", apiKey)
					req.Header.Del("Authorization")
				}
				if body != "" {
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept", "application/json")
				}
				if strings.HasPrefix(flow, "system") {
					secret := tests.TestPwd1
					if isKey {
						secret = apiKey
					}
					req = challengeSystemRequest(t, server.URL+"/auth/api/system", isKey, secret)
				}
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if mutation != "unchanged" {
					if !changed.Load() {
						t.Fatal("mutation boundary was not exercised")
					}
					if err := <-mutationResult; err != nil {
						t.Fatal("mutation failed", err)
					}
					if response.StatusCode < 400 || response.Header.Get("Authorization") != "" {
						t.Fatalf("changed identity issued credentials: HTTP %d", response.StatusCode)
					}
					for _, cookie := range response.Cookies() {
						if (cookie.Name == "AUTHP_ACCESS_TOKEN" || cookie.Name == "AUTHP_REFRESH_TOKEN") && cookie.Value != "" && cookie.MaxAge >= 0 {
							t.Fatal("changed identity received an authentication cookie")
						}
					}
					return
				}
				var token string
				switch flow {
				case "system basic", "system API key":
					challengeSystemClaims(t, payload)
					return
				case "HTTP basic":
					token = strings.TrimPrefix(response.Header.Get("Authorization"), "Bearer ")
				case "JSON API key":
					var decoded apiauth.AuthResponse
					if err := json.Unmarshal(payload, &decoded); err != nil {
						t.Fatal("invalid API key response")
					}
					token = decoded.AccessToken
				default:
					token = string(payload)
				}
				claims := loginIdentityClaims(t, f, token, "alice")
				if isKey && claims["amr"] != nil {
					t.Fatal("API key acquired password or MFA evidence")
				}
			})
		}
	}
}
