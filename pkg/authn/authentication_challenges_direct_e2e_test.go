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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

func TestE2EAuthenticationChallengeDirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		stored, actions              []string
		mfa, hardware, basic, apiKey bool
	}{
		{name: "default password", basic: true, apiKey: true},
		{name: "forged AMR", actions: []string{"overwrite amr hwk"}, basic: true, apiKey: true},
		{name: "default MFA preserves API keys", mfa: true, apiKey: true},
		{name: "stored TOTP only", mfa: true, stored: []string{"totp"}},
		{name: "stored WebAuthn only", hardware: true, stored: []string{"u2f"}},
		{name: "stored password", mfa: true, stored: []string{"password"}, basic: true},
		{name: "portal password overrides defaults", mfa: true, actions: []string{"require auth challenges password"}, basic: true},
		{name: "portal TOTP only", mfa: true, actions: []string{"require auth challenges totp"}},
		{name: "additive TOTP", actions: []string{"require totp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configure := func(cfg *authn.PortalConfig) {
				challengeSystemConfig(cfg)
				if len(tc.actions) > 0 {
					authenticationChallengeConfig(t, tc.actions)(cfg)
				}
			}
			f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, tc.mfa, "", configure)
			if tc.hardware {
				portalURL, _ := url.Parse(f.server.URL)
				registration, _, _ := webAuthnE2ERegistration(t, portalURL.Hostname())
				if err := store.Request(operator.AddMfaToken, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "direct policy"}, WebAuthn: registration}); err != nil {
					t.Fatal(err)
				}
			}
			if len(tc.stored) > 0 {
				if _, err := store.OverwriteUserAuthChallengeRules("alice", "alice@example.test", tc.stored); err != nil {
					t.Fatal(err)
				}
			}
			const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
			if err := store.Request(operator.AddAPIKey, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "direct policy"}}); err != nil {
				t.Fatal(err)
			}
			// A real embedding HTTP server consumes the public BasicAuth/APIKeyAuth
			// library APIs, independently of the portal's own login routes.
			cfg := &authn.PortalConfig{Name: "direct-policy", IdentityStores: []string{store.GetName()}, RawCryptoKeyStoreConfig: []string{e2eRSAKey}}
			configure(cfg)
			portal, err := authn.NewPortal(authn.PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(portal.Close)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req := &authproxy.Request{Realm: "local", Address: "198.51.100.10", Secret: r.Header.Get("X-Test-Credential")}
				var err error
				if r.URL.Path == "/basic" {
					err = portal.BasicAuth(req)
				} else {
					err = portal.APIKeyAuth(req)
				}
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				io.WriteString(w, req.Response.Payload)
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 5 * time.Second
			for _, method := range []struct {
				path, credential string
				allowed          bool
			}{
				{"/basic", base64.StdEncoding.EncodeToString([]byte("alice:" + tests.TestPwd1)), tc.basic},
				{"/key", apiKey, tc.apiKey},
			} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+method.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-Test-Credential", method.credential)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if (resp.StatusCode == http.StatusOK) != method.allowed {
					t.Errorf("public %s status %d, allowed=%t", method.path, resp.StatusCode, method.allowed)
				} else if method.allowed {
					claims := loginIdentityClaims(t, f, string(body), "alice")
					if method.path == "/key" && claims["amr"] != nil {
						t.Fatal("API key acquired factor evidence")
					}
				} else if len(body) != 0 {
					t.Fatal("denied embedding request returned a credential")
				}
			}
			basic := passwordAttemptBasic(t, f, "198.51.100.10", tests.TestPwd1)
			want := http.StatusForbidden
			if tc.basic {
				want = http.StatusSeeOther
			}
			if basic.status != want {
				t.Errorf("portal Basic status %d, want %d", basic.status, want)
			}
			keyResponse := f.jsonRequest(t, "/login", apiauth.AuthRequest{Realm: "local", APIKey: apiKey}, "")
			want = http.StatusUnauthorized
			if tc.apiKey {
				want = http.StatusOK
			}
			if keyResponse.status != want {
				t.Errorf("portal API key status %d, want %d", keyResponse.status, want)
			}
			for _, method := range []struct {
				key, allowed bool
				secret       string
			}{{false, tc.basic, tests.TestPwd1}, {true, tc.apiKey, apiKey}} {
				response, err := f.client.Do(challengeSystemRequest(t, f.issuer+"/api/system", method.key, method.secret))
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if (response.StatusCode == http.StatusOK) != method.allowed {
					t.Errorf("system API key=%t HTTP %d, allowed=%t", method.key, response.StatusCode, method.allowed)
					continue
				}
				if method.allowed {
					claims := challengeSystemClaims(t, body)
					if method.key && claims["amr"] != nil || !method.key && !reflect.DeepEqual(claims["amr"], []any{"pwd"}) {
						t.Error("system response misstated verified authentication methods")
					}
				}
			}
		})
	}
}
