// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestE2ETokenRefreshJSONCompletionRecovery(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprintf("custom=%t", custom), func(t *testing.T) {
			var directives []string
			if custom {
				directives = []string{"cookie prefix COMPANY", "cookie refresh token name COMPANY_RENEWAL"}
			}
			cookies, err := cookieparser.NewCookieConfigFromDirectives(directives)
			if err != nil {
				t.Fatal(err)
			}
			f, _, _ := newLoginIdentityConfiguredE2E(t, true, true, false, "", func(cfg *authn.PortalConfig) {
				cfg.RefreshTokens.MaxSessions = 1
				cfg.OIDCProvider.MaxSessions = 1
				cfg.OIDCProvider.Realms = []string{"local", "excluded"}
			}, cookies)
			holder := replacementClientWithoutJar(f)
			holder.client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			origin := http.Header{"Origin": {f.server.URL}}
			replacementLogin(t, holder, "bob", "excluded", "", tests.TestPwd2, false, origin)
			if loginIdentityCookie(holder, cookies.OIDCSessionIDCookieName) == "" || loginIdentityCookie(holder, cookies.RefreshTokenCookieName) != "" {
				t.Fatal("access-only login did not occupy exactly the OIDC session")
			}
			request := apiauth.AuthRequest{Username: "alice", Realm: "local"}
			start := loginIdentityResponse(t, f.jsonRequest(t, "/login", request, "", origin))
			request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
			request.ChallengeKind, request.ChallengeResponse = start.NextChallenge, tests.TestPwd1
			denied := f.jsonRequest(t, "/login", request, "", origin)
			oidcE2EStatus(t, denied, http.StatusServiceUnavailable)
			if loginIdentityCookie(f, cookies.RefreshTokenCookieName) != "" || loginIdentityCookie(f, cookies.AccessTokenCookieName) != "" {
				t.Fatal("failed login delivered credentials")
			}
			// Release only the OIDC admission bottleneck through its actual browser API.
			headers := http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}
			oidcE2EStatus(t, holder.jsonRequest(t, "/api/logout", map[string]any{}, "", headers), http.StatusOK)
			_, result := replacementLogin(t, f, "alice", "local", "", tests.TestPwd1, false, origin)
			if result.SessionID == "" || loginIdentityCookie(f, cookies.RefreshTokenCookieName) == "" {
				t.Fatal("refresh capacity did not recover")
			}
			rotated := loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers))
			if rotated.SessionID != result.SessionID {
				t.Fatal("recovery changed the authenticated family")
			}
			loginIdentityClaims(t, f, loginIdentityCookie(f, cookies.AccessTokenCookieName), "alice")
		})
	}
}
