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
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EOAuthApplicationRegistrationReload(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "none"} {
		t.Run(method, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "users.json")
			db, err := identity.NewDatabase(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
				t.Fatal("could not provision local user")
			}
			keyFile := filepath.Join(dir, "signing key.pem")
			if err := oidc.GenerateSigningKeyFile(keyFile); err != nil {
				t.Fatal(err)
			}
			var active atomic.Pointer[authn.Portal]
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := active.Load().ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
					t.Error("portal request failed")
				}
			}))
			t.Cleanup(server.Close)
			issuer := "https://" + server.Listener.Addr().String() + "/auth"
			callbacks := []string{"https://RP.example.test:443/a%2Fb?registered=yes&next=%2F&x=+", "https://rp.example.test/callback?registered=yes"}
			callback := callbacks[0]
			body := []string{cfgutil.EncodeArgs([]string{"redirect_uri", callbacks[0]}), "token_endpoint_auth_method " + method, cfgutil.EncodeArgs([]string{"redirect_uri", callbacks[1]}), "skip_consent on"}
			client, err := oidcparser.NewOIDCClientConfigFromDirectives("website", body)
			if err != nil {
				t.Fatal(err)
			}
			registration, err := oidc.NewOAuthApplicationConfig("website", client)
			if err != nil {
				t.Fatal(err)
			}
			// This fixture models a host secret store. Provision once, persist a
			// complete registration privately, and reopen it on every adaptation.
			stateFile := filepath.Join(dir, "applications.json")
			state, err := json.Marshal(&authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{registration}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stateFile, state, 0600); err != nil {
				t.Fatal(err)
			}
			if info, err := os.Stat(stateFile); err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("credential persistence is not private")
			}
			if result, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application website", body, nil); result != nil || err == nil {
				t.Fatal("missing persisted credentials silently provisioned a new identity")
			}
			var f *oidcE2EFixture
			var subject, previousToken string
			stages := []string{"initial", "reload"}
			if method != "none" {
				stages = append(stages, "rotate secret", "reload rotated secret")
			}
			for _, stage := range stages {
				t.Run(stage, func(t *testing.T) {
					var saved authcrunch.Config
					if err := saved.LoadFromJSONFile(stateFile); err != nil {
						t.Fatal(err)
					}
					previous, err := saved.GetOAuthApplication("website")
					if err != nil {
						t.Fatal(err)
					}
					currentBody := append([]string(nil), body...)
					secret := previous.Client.ClientSecret
					if stage == "rotate secret" {
						secret = oidc.GenerateClientSecret()
						currentBody = append(currentBody, cfgutil.EncodeArgs([]string{"client_secret", secret}))
					}
					application, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application website", currentBody, previous)
					if err != nil {
						t.Fatal(err)
					}
					if application.Client.ClientID != client.ClientID || application.Client.ClientSecret != secret || !slices.Equal(application.Client.RedirectURIs, callbacks) {
						t.Fatal("adaptation changed expected client credentials or callbacks")
					}
					state, err := json.Marshal(&authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{application}})
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(stateFile, state, 0600); err != nil {
						t.Fatal(err)
					}
					config := &authcrunch.Config{IdentityStores: []*ids.IdentityStoreConfig{{Name: "local-store", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}}}
					if err := config.AddOAuthApplication(application); err != nil {
						t.Fatal(err)
					}
					unselected, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application unselected", []string{"client_id unselected-id", "token_endpoint_auth_method none", "redirect_uri " + callback}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := config.AddOAuthApplication(unselected); err != nil {
						t.Fatal(err)
					}
					portalConfig := &authn.PortalConfig{Name: "oidc-applications", IdentityStores: []string{"local-store"}}
					// Even when added/validated first, provider attachment must apply
					// OIDC cookie/API defaults before constructing the real portal.
					if err := config.AddAuthenticationPortal(portalConfig); err != nil {
						t.Fatal(err)
					}
					if err := config.ConfigureOIDCProvider(portalConfig, []string{
						cfgutil.EncodeArgs([]string{"issuer", issuer}), "realms local",
						cfgutil.EncodeArgs([]string{"signing", "key", "files", keyFile}), "applications website",
					}); err != nil {
						t.Fatal(err)
					}
					runtime, err := authcrunch.NewServer(config, zap.NewNop())
					if err != nil {
						t.Fatal(err)
					}
					portal, err := runtime.GetPortalByName("oidc-applications")
					if err != nil {
						t.Fatal(err)
					}
					if old := active.Swap(portal); old != nil {
						old.Close()
					}
					if f == nil {
						server.StartTLS()
						httpClient := server.Client()
						httpClient.Timeout = 10 * time.Second
						httpClient.Jar, _ = cookiejar.New(nil)
						httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
						f = &oidcE2EFixture{server: server, client: httpClient, issuer: issuer, callback: callback}
					}
					if previousToken != "" {
						oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + previousToken}}), http.StatusUnauthorized)
					}
					f.loginJSON(t)
					for _, id := range []string{"website", "unselected-id"} {
						params := f.authorization(id)
						// Use the unselected registration's own callback on every
						// reload so a redirect mismatch cannot mask its selection.
						params.Set("redirect_uri", callback)
						response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
						oidcE2EStatus(t, response, http.StatusBadRequest)
						if response.header.Get("Location") != "" {
							t.Fatal("unknown or unselected application redirected")
						}
					}
					for _, unregistered := range []string{
						callbacks[0] + "&unregistered=1",
						strings.Replace(callbacks[0], "RP.", "rp.", 1),
						strings.Replace(callbacks[0], ":443", "", 1),
						strings.Replace(callbacks[0], "%2F", "%2f", 1),
						strings.Replace(callbacks[0], "/a%2Fb", "/a/b", 1),
						strings.Replace(callbacks[0], "x=+", "x=%20", 1),
					} {
						params := f.authorization(client.ClientID)
						params.Set("redirect_uri", unregistered)
						denied := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
						oidcE2EStatus(t, denied, http.StatusBadRequest)
						if denied.header.Get("Location") != "" {
							t.Fatal("unregistered callback redirected")
						}
					}
					for i, callback := range callbacks {
						f.callback = callback
						response := f.request(t, "GET", "/oidc/authorize?"+f.authorization(client.ClientID).Encode(), nil, nil)
						code := oidcProviderE2ECode(t, response)
						target, err := url.Parse(response.header.Get("Location"))
						if err != nil {
							t.Fatal("invalid callback URI")
						}
						expected, err := url.Parse(callback)
						if err != nil {
							t.Fatal("invalid registered callback")
						}
						if target.Scheme != expected.Scheme || target.Host != expected.Host || target.EscapedPath() != expected.EscapedPath() {
							t.Fatal("authorization response changed the callback destination")
						}
						for key, values := range expected.Query() {
							if !slices.Equal(target.Query()[key], values) {
								t.Fatal("authorization response changed a registered query value")
							}
						}
						exchange := func(value, redirectURI string) oidcE2EResponse {
							form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {oidcE2EVerifier}}
							headers := make(http.Header)
							switch method {
							case "client_secret_basic":
								headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client.ClientID)+":"+url.QueryEscape(value))))
							case "client_secret_post":
								form.Set("client_id", client.ClientID)
								form.Set("client_secret", value)
							case "none":
								form.Set("client_id", client.ClientID)
							}
							return f.request(t, "POST", "/oidc/token", form, headers)
						}
						if method != "none" {
							incorrect := "incorrect-secret"
							if stage == "rotate secret" || stage == "reload rotated secret" {
								incorrect = client.ClientSecret
							}
							oidcE2EStatus(t, exchange(incorrect, callback), http.StatusUnauthorized)
						}
						// Registration of both callbacks must not allow exchanging
						// a code at a different callback from the one authorized.
						wrongCallback := exchange(secret, callbacks[(i+1)%len(callbacks)])
						oidcE2EStatus(t, wrongCallback, http.StatusBadRequest)
						var failure struct {
							Error string `json:"error"`
						}
						if json.Unmarshal(wrongCallback.body, &failure) != nil || failure.Error != "invalid_grant" {
							t.Fatal("callback substitution did not reject the grant")
						}
						tokens := oidcE2ETokens(t, exchange(secret, callback))
						claims := f.verifyIDToken(t, tokens, client.ClientID)
						if subject != "" && claims["sub"] != subject {
							t.Fatal("configuration reload changed local subject identity")
						}
						subject = claims["sub"].(string)
						previousToken = tokens["access_token"].(string)
						userInfo := f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + previousToken}})
						oidcE2EStatus(t, userInfo, http.StatusOK)
						var profile map[string]any
						if json.Unmarshal(userInfo.body, &profile) != nil || profile["sub"] != subject || profile["email"] != "alice@example.test" {
							t.Fatal("registered application did not receive authorized identity")
						}
					}
				})
				if t.Failed() {
					break
				}
			}
			server.Close()
			if portal := active.Load(); portal != nil {
				portal.Close()
			}
		})
	}
}
