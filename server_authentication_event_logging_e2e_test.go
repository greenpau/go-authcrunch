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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	loggingparser "github.com/greenpau/go-authcrunch/pkg/logging/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EServerAuthenticationEvents(t *testing.T) {
	for _, selected := range []string{"", "event-portal-alpha", "event-realm-one"} {
		name := selected
		if name == "" {
			name = "unfiltered"
		}
		t.Run(name, func(t *testing.T) {
			secrets := []string{tests.TestPwd1, tests.TestPwd2}
			core, logs := observer.New(zap.InfoLevel)
			logger := zap.New(core)
			t.Cleanup(func() { assertServerAuthenticationEventSecrets(t, logs, secrets) })
			key := []string{"crypto key event-test sign-verify from file testdata/rskeys/test_2_pri.pem"}
			cfg := &authcrunch.Config{
				AuthorizationPolicies: []*authz.PolicyConfig{{Name: "event-policy", RawCryptoKeyStoreConfig: key, AuthRedirectDisabled: true, ValidateBearerHeader: true, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}},
			}
			for _, realm := range []string{"event-realm-one", "event-realm-two"} {
				dbPath := filepath.Join(t.TempDir(), "users.json")
				db, err := identity.NewDatabase(dbPath)
				if err != nil {
					t.Fatal("could not create event identity database")
				}
				if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
					t.Fatal("could not provision event identity")
				}
				cfg.IdentityStores = append(cfg.IdentityStores, &ids.IdentityStoreConfig{Name: realm, Kind: "local", Params: map[string]any{"realm": realm, "path": dbPath}})
			}
			for _, portal := range []string{"event-portal-alpha", "event-portal-beta"} {
				cfg.AuthenticationPortals = append(cfg.AuthenticationPortals, &authn.PortalConfig{
					Name: portal, IdentityStores: []string{"event-realm-one", "event-realm-two"}, RawCryptoKeyStoreConfig: key,
					UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"exact match sub alice"}, Actions: []string{"overwrite sub display-alias"}}},
				})
			}
			if selected != "" {
				var err error
				cfg.Logging, err = loggingparser.NewLoggingConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"skip", "exact", "text", selected})})
				if err != nil {
					t.Fatal("could not parse event field-value filter")
				}
			}
			runtime, err := authcrunch.NewServer(cfg, logger)
			if err != nil {
				t.Fatal("could not construct event root")
			}
			t.Cleanup(func() {
				if err := runtime.Close(); err != nil {
					t.Error("event root cleanup failed")
				}
			})
			portals := make(map[string]*authn.Portal)
			for _, mount := range []string{"alpha", "beta"} {
				portal, err := runtime.GetPortalByName("event-portal-" + mount)
				if err != nil {
					t.Fatal("could not resolve event portal")
				}
				portals[mount] = portal
			}
			gate, err := runtime.GetGatekeeperByName("event-policy")
			if err != nil {
				t.Fatal("could not resolve event policy")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/protected" {
					ar := requests.NewAuthorizationRequest()
					if err := gate.Authenticate(w, r, ar); err != nil || !ar.Response.Authorized {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
				portal := portals[parts[0]]
				if portal == nil {
					http.NotFound(w, r)
					return
				}
				rr := requests.NewRequest()
				// This wrapper supplies an explicit correlation value. It does not
				// authenticate it or equate it with the server-held identity.
				rr.ID = r.Header.Get("X-Event-Request")
				if err := portal.ServeHTTP(r.Context(), w, r, rr); err != nil {
					t.Error("event portal request failed")
				}
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 10 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			authorize := func(token string, want int) {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/protected", nil)
				if err != nil {
					t.Fatal("could not construct protected event request")
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				response, err := client.Do(req)
				if err != nil {
					t.Fatal("protected event request failed")
				}
				defer response.Body.Close()
				if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4097)); err != nil {
					t.Fatal("could not read protected event response")
				}
				if response.StatusCode != want {
					t.Fatalf("protected event response returned HTTP %d, want %d", response.StatusCode, want)
				}
			}
			post := func(mount, requestID string, request apiauth.AuthRequest, want int) apiauth.AuthResponse {
				t.Helper()
				body, err := json.Marshal(request)
				if err != nil {
					t.Fatal("could not encode event login request")
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/"+mount+"/auth/login", bytes.NewReader(body))
				if err != nil {
					t.Fatal("could not construct event login request")
				}
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Event-Request", requestID)
				response, err := client.Do(req)
				if err != nil {
					t.Fatal("event login request failed")
				}
				defer response.Body.Close()
				data, err := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
				if err != nil || len(data) > 16<<10 {
					t.Fatal("could not read bounded event login response")
				}
				var result apiauth.AuthResponse
				decodeErr := json.Unmarshal(data, &result)
				secrets = append(secrets, result.SandboxSecret, result.AccessToken, result.RefreshToken)
				for _, cookie := range response.Cookies() {
					if cookie.Name == "AUTHP_SANDBOX_ID" || cookie.Name == "AUTHP_ACCESS_TOKEN" || cookie.Name == "AUTHP_REFRESH_TOKEN" || cookie.Name == "AUTHP_OIDC_SESSION_ID" {
						secrets = append(secrets, cookie.Value)
						if !result.Authenticated && cookie.Name != "AUTHP_SANDBOX_ID" && cookie.Value != "" && cookie.MaxAge >= 0 && (cookie.Expires.IsZero() || cookie.Expires.After(time.Now())) {
							t.Fatal("unfinished login delivered an active credential cookie")
						}
					}
				}
				if response.StatusCode != want || decodeErr != nil {
					t.Fatalf("event login response returned HTTP %d, want %d, JSON valid=%t", response.StatusCode, want, decodeErr == nil)
				}
				if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("event login response lost verified TLS or cache protection")
				}
				return result
			}
			for _, mount := range []string{"alpha", "beta"} {
				for _, realm := range []string{"event-realm-one", "event-realm-two"} {
					for _, accepted := range []bool{false, true} {
						label := fmt.Sprintf("%s-%s-accepted-%t", mount, realm, accepted)
						start := post(mount, "start-"+label, apiauth.AuthRequest{Username: "alice@example.test", Realm: realm}, http.StatusOK)
						if start.NextChallenge != "password" || start.SandboxID == "" || start.SandboxSecret == "" || start.Authenticated || start.AccessToken != "" || start.RefreshToken != "" {
							t.Fatal("initial event login did not require its password checkpoint")
						}
						if logs.FilterMessage("user was successfully authenticated").FilterField(zap.String("request_id", "start-"+label)).Len() != 0 {
							t.Fatal("initial checkpoint logged final success")
						}
						password, want, message, level := tests.TestPwd2, http.StatusUnauthorized, "password authentication failed", zap.WarnLevel
						if accepted {
							password, want, message, level = tests.TestPwd1, http.StatusOK, "user was successfully authenticated", zap.InfoLevel
						}
						result := post(mount, label, apiauth.AuthRequest{Username: "alice@example.test", Realm: realm, SandboxID: start.SandboxID, SandboxSecret: start.SandboxSecret, ChallengeKind: "password", ChallengeResponse: password}, want)
						if accepted {
							if !result.Authenticated || result.AccessToken == "" {
								t.Fatal("completed login did not return access credentials")
							}
							authorize(result.AccessToken, http.StatusNoContent)
						} else {
							if result.Authenticated || result.AccessToken != "" || result.RefreshToken != "" {
								t.Fatal("failed login returned credentials")
							}
							authorize("", http.StatusUnauthorized)
							if logs.FilterMessage("user was successfully authenticated").FilterField(zap.String("request_id", label)).Len() != 0 {
								t.Fatal("failed password logged final success")
							}
						}
						entries := logs.FilterMessage(message).FilterField(zap.String("request_id", label)).All()
						filtered := selected == "event-portal-"+mount || selected == realm
						if filtered {
							if len(entries) != 0 {
								t.Fatal("field-value filter retained its selected event")
							}
							continue
						}
						if len(entries) != 1 || entries[0].Level != level {
							t.Fatal("unfiltered authentication event count or level is incorrect")
						}
						fields := entries[0].ContextMap()
						if fields["portal_name"] != "event-portal-"+mount || fields["realm"] != realm || fields["username"] != "alice" || fields["session_id"] == "" || fields["session_id"] == nil {
							t.Fatal("event did not retain canonical portal, realm, account and correlation")
						}
						if accepted {
							if fields["authentication_flow"] != "api" {
								t.Fatal("JSON success event lost its flow marker")
							}
						} else if fields["checkpoint_type"] != "password" || fields["checkpoint_name"] == "" || fields["checkpoint_id"] == nil || fields["src_ip"] != "127.0.0.1" || fields["src_conn_ip"] != "127.0.0.1" {
							t.Fatal("factor failure event lost checkpoint or source metadata")
						}
					}
				}
			}
		})
	}
}

func assertServerAuthenticationEventSecrets(t testing.TB, logs *observer.ObservedLogs, secrets []string) {
	t.Helper()
	for _, entry := range logs.All() {
		encoded, err := json.Marshal(entry.ContextMap())
		if err != nil {
			t.Fatal("could not inspect authentication event fields")
		}
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			quoted, _ := json.Marshal(secret)
			if strings.Contains(entry.Message, secret) || bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, quoted[1:len(quoted)-1]) {
				t.Fatal("authentication events exposed a fixture credential")
			}
		}
	}
}
