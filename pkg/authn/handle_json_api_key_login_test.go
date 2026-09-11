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

package authn

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestPortalAPIKeyLoginAccessOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "refresh disabled"
		if enabled {
			name = "refresh enabled"
		}
		t.Run(name, func(t *testing.T) {
			f := newRefreshPortal(t, enabled, false)
			key := strings.Repeat("a", 64)
			req := requests.NewRequest()
			req.User.Username, req.User.Email = tests.TestUser1, tests.TestEmail1
			req.Key = requests.Key{Payload: key, Usage: "api", Comment: "test API key"}
			if err := f.store.Request(operator.AddAPIKey, req); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name   string
				fields map[string]string
				status int
			}{
				{name: "API key credential", status: http.StatusOK},
				{name: "username conflict", fields: map[string]string{"username": tests.TestUser1}, status: http.StatusBadRequest},
				{name: "sandbox conflict", fields: map[string]string{"sandbox_id": "id", "sandbox_secret": "secret", "challenge_kind": "password", "challenge_response": "answer"}, status: http.StatusBadRequest},
				{name: "native refresh forbidden", fields: map[string]string{"refresh_transport": "body"}, status: http.StatusBadRequest},
				{name: "wrong secret", fields: map[string]string{"api_key": key[:63] + "b"}, status: http.StatusUnauthorized},
			} {
				t.Run(tc.name, func(t *testing.T) {
					fields := map[string]string{"api_key": key, "realm": "local"}
					for name, value := range tc.fields {
						fields[name] = value
					}
					body, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					w := f.request(t, http.MethodPost, "/auth/login", string(body), false)
					if w.Code != tc.status {
						t.Fatalf("got HTTP %d, want %d", w.Code, tc.status)
					}
					if strings.Contains(w.Body.String(), key) {
						t.Fatal("API key leaked in response")
					}
					var response apiauth.AuthResponse
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal("invalid JSON response")
					}
					if response.RefreshToken != "" || response.SessionID != "" {
						t.Fatal("API key login created a renewable session")
					}
					if tc.status != http.StatusOK {
						if response.Authenticated || response.AccessToken != "" {
							t.Fatal("rejected request returned credentials")
						}
						return
					}
					if !response.Authenticated || response.AccessToken == "" || response.AccessTokenName != f.portal.GetAccessTokenCookieName() {
						t.Fatal("API key login did not return access credentials")
					}
					if len(w.Header().Values("Set-Cookie")) != 0 || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
						t.Fatal("API key response set cookies or allowed caching")
					}
				})
			}
		})
	}
}
