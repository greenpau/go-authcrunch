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
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func TestE2EAuthenticationChallengeRequestContext(t *testing.T) {
	for _, matcher := range []string{"prefix match iss https://", "exact match addr 127.0.0.1"} {
		for _, features := range []struct{ refresh, oidc bool }{{}, {refresh: true}, {oidc: true}, {refresh: true, oidc: true}} {
			for _, flow := range []string{"html", "json"} {
				t.Run(fmt.Sprintf("%s/refresh=%t/oidc=%t/%s", matcher, features.refresh, features.oidc, flow), func(t *testing.T) {
					f, _, _ := newLoginIdentityConfiguredE2E(t, features.refresh, features.oidc, true, "", authenticationChallengeConfig(t, []string{matcher, "require auth challenges totp"}))
					token := authenticationChallengeLogin(t, f, flow, []string{"totp"}, nil, "")
					if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[otp]" {
						t.Fatal("contextual policy lost verified methods")
					}
					if features.oidc {
						code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
						tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
						if claims := f.verifyIDToken(t, tokens, "second"); fmt.Sprint(claims["amr"]) != "[otp]" {
							t.Fatal("OIDC lost contextual policy evidence")
						}
					}
					if features.refresh {
						oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}), http.StatusOK)
						if claims := loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice"); fmt.Sprint(claims["amr"]) != "[otp]" {
							t.Fatal("refresh lost contextual policy evidence")
						}
					}
				})
			}
		}
	}
}

func TestE2EAuthenticationChallengeContextChange(t *testing.T) {
	for _, operation := range []string{"authorize", "code", "userinfo", "oidc refresh", "portal refresh"} {
		t.Run(operation, func(t *testing.T) {
			f, _, _ := newLoginIdentityConfiguredE2E(t, true, true, true, "", func(cfg *authn.PortalConfig) {
				authenticationChallengeConfig(t, []string{"require auth challenges password"})(cfg)
				authenticationChallengeConfig(t, []string{"exact match addr 198.51.100.10", "require totp"})(cfg)
				cfg.OIDCProvider.Clients[0].Scopes = []string{"openid", "offline_access"}
			})
			token := authenticationChallengeLogin(t, f, "html", []string{"password"}, nil, "")
			if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[pwd]" {
				t.Fatal("unexpected initial authentication evidence")
			}
			changed := http.Header{"X-Real-IP": {"198.51.100.10"}}
			params := f.authorization("second")
			if operation == "authorize" {
				params.Set("prompt", "none")
				response := f.request(t, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, changed)
				target, err := url.Parse(response.header.Get("Location"))
				if err != nil || target.Query().Get("error") != "login_required" || target.Query().Get("code") != "" {
					t.Fatal("authorization ignored the current request's factor requirement")
				}
				return
			}
			if operation == "portal refresh" {
				changed.Set("Origin", f.server.URL)
				changed.Set("X-Authcrunch-Refresh", "1")
				oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", changed), http.StatusUnauthorized)
				return
			}
			if operation == "oidc refresh" {
				params.Set("scope", "openid offline_access")
				params.Set("prompt", "consent")
			}
			authorized := f.request(t, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, nil)
			if operation == "oidc refresh" {
				authorized = f.approve(t, authorized, "allow")
			}
			code := oidcProviderE2ECode(t, authorized)
			changed.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("second:"+oidcE2ESecret)))
			if operation == "code" {
				form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.callback}, "code_verifier": {oidcE2EVerifier}, "client_id": {"second"}}
				oidcE2EError(t, f.request(t, http.MethodPost, "/oidc/token", form, changed), "invalid_grant")
				return
			}
			tokens := oidcClaimsTokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
			if claims := f.verifyIDToken(t, tokens, "second"); fmt.Sprint(claims["amr"]) != "[pwd]" {
				t.Fatal("OIDC issued unverified methods")
			}
			if operation == "userinfo" {
				changed.Set("Authorization", "Bearer "+tokens["access_token"].(string))
				oidcE2EStatus(t, f.request(t, http.MethodGet, "/oidc/userinfo", nil, changed), http.StatusUnauthorized)
				return
			}
			refresh, ok := tokens["refresh_token"].(string)
			if !ok || refresh == "" {
				t.Fatal("offline consent did not issue a refresh token")
			}
			oidcE2EError(t, f.request(t, http.MethodPost, "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, changed), "invalid_grant")
		})
	}
}
