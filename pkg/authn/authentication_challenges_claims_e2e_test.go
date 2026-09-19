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
	"reflect"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func TestE2EAuthenticationChallengeClaimSafety(t *testing.T) {
	for _, renewable := range []bool{false, true} {
		for _, flow := range []string{"html", "json"} {
			for _, tc := range []struct {
				name    string
				actions []string
				denied  bool
			}{
				{"nested collision", []string{"add nested roles flow with totp as string"}, true},
				{"literal claim value", []string{
					"overwrite name }}{claims.sub}", "add display_name {claims.name} as string", "add name suffix",
					"add nested client as map", "add nested client flow with totp as string",
					"add nested client scopes with read write as string list", "add labels alpha beta as list",
				}, false},
			} {
				t.Run(fmt.Sprintf("renewable=%t/%s/%s", renewable, flow, tc.name), func(t *testing.T) {
					actions := append(tc.actions, "require auth challenges totp")
					f, _, _ := newLoginIdentityConfiguredE2E(t, renewable, renewable, true, "", authenticationChallengeConfig(t, actions))
					if tc.denied {
						var response oidcE2EResponse
						if flow == "json" {
							response = f.jsonRequest(t, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local"}, "")
						} else {
							response = f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, nil)
						}
						if response.status != http.StatusBadRequest {
							t.Fatalf("claim collision HTTP %d", response.status)
						}
						if response.header.Get("Authorization") != "" || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
							t.Fatal("claim collision issued credentials")
						}
						return
					}
					token := authenticationChallengeLogin(t, f, flow, []string{"totp"}, nil, "")
					checkClaims := func(token string) {
						t.Helper()
						claims := loginIdentityClaims(t, f, token, "alice")
						if claims["display_name"] != "}}{claims.sub}" || claims["name"] != "}}{claims.sub} suffix" || fmt.Sprint(claims["amr"]) != "[otp]" {
							t.Fatal("claim interpolation changed data or policy evidence")
						}
						nested, ok := claims["client"].(map[string]any)
						if !ok || nested["flow"] != "totp" || !reflect.DeepEqual(nested["scopes"], []any{"read", "write"}) || !reflect.DeepEqual(claims["labels"], []any{"alpha", "beta"}) {
							t.Fatal("custom scalar/list/map claims missing")
						}
					}
					checkClaims(token)
					origin := http.Header{"Origin": {f.server.URL}}
					preview := f.jsonRequest(t, "/api/profile", map[string]any{"kind": "fetch_user_auth_challenges"}, token, origin)
					if flow == "json" && !renewable {
						// Access-only native tokens do not establish a browser
						// session carrying current local profile authority.
						oidcE2EStatus(t, preview, http.StatusUnauthorized)
					} else {
						profileAuthChallengeResponse(t, preview, "portal", nil, []string{"password", "totp"}, []string{"totp"}, nil, false)
					}
					if renewable {
						code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
						tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
						if claims := f.verifyIDToken(t, tokens, "second"); fmt.Sprint(claims["amr"]) != "[otp]" {
							t.Fatal("OIDC changed method evidence")
						}
						oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}), http.StatusOK)
						checkClaims(loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"))
					}
				})
			}
		}
	}
}
