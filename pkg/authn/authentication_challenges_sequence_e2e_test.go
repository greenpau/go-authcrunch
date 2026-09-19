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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EAuthenticationChallengeSequences(t *testing.T) {
	for _, renewable := range []bool{false, true} {
		for _, flow := range []string{"html", "json"} {
			for _, tc := range []struct {
				name, amr         string
				sequence, actions []string
			}{
				{name: "hardware then password", sequence: []string{"u2f", "password"}, amr: "[hwk pwd]"},
				{name: "hardware then TOTP", sequence: []string{"u2f", "totp"}, amr: "[hwk otp]"},
				{name: "hardware in middle", sequence: []string{"password", "u2f", "totp"}, amr: "[pwd hwk otp]"},
				{name: "hardware last", sequence: []string{"totp", "u2f"}, amr: "[otp hwk]"},
				{name: "additive password", sequence: []string{"u2f", "password"}, actions: []string{"require auth challenges u2f", "require password"}, amr: "[hwk pwd]"},
			} {
				t.Run(fmt.Sprintf("renewable=%t/%s/%s", renewable, flow, tc.name), func(t *testing.T) {
					actions := tc.actions
					if actions == nil {
						actions = []string{"require auth challenges " + strings.Join(tc.sequence, " ")}
					}
					f, store, _ := newLoginIdentityConfiguredE2E(t, renewable, renewable, true, "", authenticationChallengeConfig(t, actions))
					portalURL, _ := url.Parse(f.server.URL)
					registration, key, credentialID := webAuthnE2ERegistration(t, portalURL.Hostname())
					if err := store.Request(operator.AddMfaToken, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "ordered checkpoints"}, WebAuthn: registration}); err != nil {
						t.Fatal(err)
					}
					token := authenticationChallengeLogin(t, f, flow, tc.sequence, key, credentialID)
					if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != tc.amr {
						t.Fatalf("authentication methods %v, want %s", claims["amr"], tc.amr)
					}
					if renewable {
						code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
						tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
						if claims := f.verifyIDToken(t, tokens, "second"); fmt.Sprint(claims["amr"]) != tc.amr {
							t.Fatal("OIDC changed completed factor sequence")
						}
						oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}), http.StatusOK)
						if claims := loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice"); fmt.Sprint(claims["amr"]) != tc.amr {
							t.Fatal("refresh changed completed factor sequence")
						}
					}
				})
			}
		}
	}
}
