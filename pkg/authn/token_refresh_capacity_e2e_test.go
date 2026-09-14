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
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2ERefreshCapacityBrowser(t *testing.T) {
	for _, custom := range []bool{false, true} {
		for _, flow := range []string{"html", "json"} {
			t.Run(fmt.Sprintf("custom=%t/%s", custom, flow), func(t *testing.T) {
				var directives []string
				if custom {
					directives = []string{"cookie prefix CUSTOM", "cookie refresh token name CUSTOM_RENEWAL"}
				}
				cookies, err := cookieparser.NewCookieConfigFromDirectives(directives)
				if err != nil {
					t.Fatal(err)
				}
				f, _, _ := newLoginIdentityConfiguredE2E(t, true, false, false, "", func(cfg *authn.PortalConfig) {
					var err error
					cfg.RefreshTokens, err = refreshparser.NewTokenRefreshConfigFromDirectives([]string{
						cfgutil.EncodeArgs([]string{"realms", "local"}),
						cfgutil.EncodeArgs([]string{"public", "origin", cfg.RefreshTokens.PublicOrigin}),
						cfgutil.EncodeArgs([]string{"base", "path", "/auth"}),
						"max sessions 1", "max rotations 3", "body transport enabled",
					})
					if err != nil {
						t.Fatal(err)
					}
				}, cookies)
				origin := http.Header{"Origin": {f.server.URL}}
				headers := http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}
				login := func(name, realm, password string) {
					t.Helper()
					if flow == "html" {
						start := f.request(t, http.MethodPost, "/login?fresh=1", url.Values{"username": {name}, "realm": {realm}}, origin)
						oidcE2EStatus(t, start, http.StatusSeeOther)
						sandbox := start.header.Get("Location")
						oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {password}}, origin), http.StatusSeeOther)
						oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
					} else {
						replacementLogin(t, f, name, realm, "", password, false, origin)
					}
					claims := loginIdentityClaims(t, f, loginIdentityCookie(f, cookies.AccessTokenCookieName), name)
					if claims["origin"] != realm {
						t.Fatal("capacity admission changed identity realm")
					}
					oidcE2EStatus(t, f.request(t, http.MethodGet, "/whoami", nil, nil), http.StatusOK)
				}
				rejectOld := func(credential string) {
					t.Helper()
					old := replacementClientWithoutJar(f)
					h := headers.Clone()
					h.Set("Cookie", cookies.RefreshTokenCookieName+"="+credential)
					oidcE2EStatus(t, old.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", h), http.StatusUnauthorized)
				}
				login("alice", "local", tests.TestPwd1)
				old := loginIdentityCookie(f, cookies.RefreshTokenCookieName)
				// A separately authenticated native client cannot evict the only live
				// browser family merely because the store is full.
				native := replacementClientWithoutJar(f)
				request := apiauth.AuthRequest{Username: "bob", Realm: "local", RefreshTransport: "body"}
				start := loginIdentityResponse(t, native.jsonRequest(t, "/login", request, "", nil))
				request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
				request.ChallengeKind, request.ChallengeResponse = start.NextChallenge, tests.TestPwd2
				denied := native.jsonRequest(t, "/login", request, "", nil)
				oidcE2EStatus(t, denied, http.StatusServiceUnavailable)
				if len(denied.header.Values("Set-Cookie")) != 0 {
					t.Fatal("rejected native admission changed browser cookies")
				}
				// Password failure also must not retire the currently usable family.
				request = apiauth.AuthRequest{Username: "bob", Realm: "local"}
				start = loginIdentityResponse(t, f.jsonRequest(t, "/login", request, "", origin))
				request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
				request.ChallengeKind, request.ChallengeResponse = start.NextChallenge, "wrong-password"
				failed := f.jsonRequest(t, "/login", request, "", origin)
				if failed.status == http.StatusOK || loginIdentityCookie(f, cookies.RefreshTokenCookieName) != old {
					t.Fatal("failed authentication replaced browser session")
				}
				loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers))
				current := loginIdentityCookie(f, cookies.RefreshTokenCookieName)
				// Replacement succeeds at capacity one and retires current plus spent
				// credentials together. A late old replay cannot revoke the new family.
				login("bob", "local", tests.TestPwd2)
				rejectOld(old)
				rejectOld(current)
				loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers))
				loginIdentityClaims(t, f, loginIdentityCookie(f, cookies.AccessTokenCookieName), "bob")
				current = loginIdentityCookie(f, cookies.RefreshTokenCookieName)
				login("alice", "excluded", tests.TestPwd1)
				rejectOld(current)
				if loginIdentityCookie(f, cookies.RefreshTokenCookieName) != "" {
					t.Fatal("access-only replacement retained refresh cookie")
				}
				for range 3 {
					login("alice", "local", tests.TestPwd1)
					current = loginIdentityCookie(f, cookies.RefreshTokenCookieName)
					oidcE2EStatus(t, f.jsonRequest(t, "/api/logout", map[string]any{}, "", headers), http.StatusOK)
					login("bob", "local", tests.TestPwd2)
					rejectOld(current)
					loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers))
					oidcE2EStatus(t, f.jsonRequest(t, "/api/logout", map[string]any{}, "", headers), http.StatusOK)
				}
			})
		}
	}
}

func TestE2ERefreshCapacityAfterLogout(t *testing.T) {
	for _, transport := range []string{"cookie", "body"} {
		t.Run(transport, func(t *testing.T) {
			f := newJWKSE2EPortalWithRefresh(t, newJWKSE2EDatabase(t), "/auth", nil, []string{"max sessions 1", "body transport enabled"})
			for range 3 {
				request := apiauth.AuthRequest{Username: "keyadmin", Realm: "local", RefreshTransport: transport}
				if transport == "body" {
					start := f.postCredentials(t, "/login", request, http.StatusOK)
					request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
					request.ChallengeKind, request.ChallengeResponse = start.NextChallenge, tests.TestPwd1
					login := f.postCredentials(t, "/login", request, http.StatusOK)
					f.postCredentials(t, "/api/logout", map[string]string{"refresh_token": login.RefreshToken}, http.StatusOK)
					f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, http.StatusUnauthorized)
				} else {
					start, _ := f.browserRefreshRequest(t, "/login", request, http.StatusOK)
					request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
					request.ChallengeKind, request.ChallengeResponse = start.NextChallenge, tests.TestPwd1
					_, cookies := f.browserRefreshRequest(t, "/login", request, http.StatusOK)
					credential := refreshDirectiveCookie(t, cookies, "AUTHP_REFRESH_TOKEN")
					f.browserRefreshRequest(t, "/api/logout", struct{}{}, http.StatusOK, credential)
					f.browserRefreshRequest(t, "/api/refresh_token", struct{}{}, http.StatusUnauthorized, credential)
				}
			}
		})
	}
}
