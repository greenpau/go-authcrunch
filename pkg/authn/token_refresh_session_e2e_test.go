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
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
)

func TestE2ERefreshSessionPrecondition(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprint("custom=", custom), func(t *testing.T) {
			var directives []string
			if custom {
				directives = []string{"cookie prefix CUSTOM", "cookie refresh token name CUSTOM_RENEWAL"}
			}
			cookies, err := cookieparser.NewCookieConfigFromDirectives(directives)
			if err != nil {
				t.Fatal(err)
			}
			f, _, _ := newLoginIdentityE2E(t, true, false, false, "", cookies)
			origin := http.Header{"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}}
			_, first := replacementLogin(t, f, "alice", "local", "", tests.TestPwd1, false, origin)
			_, second := replacementLogin(t, f, "bob", "local", "", tests.TestPwd2, false, origin)
			headers := http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}
			current := loginIdentityCookie(f, cookies.RefreshTokenCookieName)
			for range 2 {
				response := f.jsonRequest(t, "/api/refresh_session", map[string]any{}, "", headers)
				oidcE2EStatus(t, response, http.StatusOK)
				var metadata map[string]string
				if json.Unmarshal(response.body, &metadata) != nil || len(metadata) != 1 || metadata["session_id"] != second.SessionID {
					t.Fatal("TLS lookup did not identify the current browser family")
				}
				if loginIdentityCookie(f, cookies.RefreshTokenCookieName) != current {
					t.Fatal("lookup rotated a credential")
				}
			}
			headers.Set("X-Authcrunch-Refresh-Session", first.SessionID)
			oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers), http.StatusUnauthorized)
			if loginIdentityCookie(f, cookies.RefreshTokenCookieName) != current {
				t.Fatal("old session precondition changed the new account's cookie")
			}
			headers.Set("X-Authcrunch-Refresh-Session", second.SessionID)
			response := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers)
			oidcE2EStatus(t, response, http.StatusOK)
			var metadata apiauth.AuthResponse
			if json.Unmarshal(response.body, &metadata) != nil || metadata.SessionID != second.SessionID || metadata.AccessToken != "" || metadata.RefreshToken != "" {
				t.Fatal("bound browser rotation lost its family or disclosed credentials")
			}
			loginIdentityClaims(t, f, loginIdentityCookie(f, cookies.AccessTokenCookieName), "bob")
			oidcE2EStatus(t, f.request(t, http.MethodGet, "/whoami", nil, nil), http.StatusOK)
		})
	}
}
