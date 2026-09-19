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
	"net/http"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EAuthenticationChallengeAPIKeyRequestContext(t *testing.T) {
	for _, tc := range []struct {
		name, matcher, action string
		allowed               bool
	}{
		{"issuer additive", "prefix match iss https://", "require totp", false},
		{"issuer replacement", "prefix match iss https://", "require auth challenges password", false},
		{"issuer deny", "prefix match iss https://", "deny", false},
		{"login path", "suffix match iss /auth/login", "require totp", false},
		{"source address", "exact match addr 198.51.100.10", "require totp", false},
		{"different issuer", "prefix match iss https://other.example.test/", "require totp", true},
		{"different path", "suffix match iss /auth/api/system", "require totp", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", authenticationChallengeConfig(t, []string{tc.matcher, tc.action}))
			const secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
			if err := store.Request(operator.AddAPIKey, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: secret, Usage: "api", Comment: "HTTP policy context"}}); err != nil {
				t.Fatal(err)
			}
			response := f.jsonRequest(t, "/login?context=ignored", apiauth.AuthRequest{Realm: "local", APIKey: secret}, "", http.Header{"X-Forwarded-For": []string{"198.51.100.10"}})
			want := http.StatusUnauthorized
			if tc.allowed {
				want = http.StatusOK
			}
			if response.status != want {
				t.Fatalf("HTTP API-key policy returned %d, want %d", response.status, want)
			}
			var result apiauth.AuthResponse
			if err := json.Unmarshal(response.body, &result); err != nil {
				t.Fatal(err)
			}
			if tc.allowed {
				claims := loginIdentityClaims(t, f, result.AccessToken, "alice")
				if claims["iss"] != f.issuer+"/login" {
					t.Fatal("HTTP API-key token did not retain the query-free login issuer")
				}
				if claims["amr"] != nil {
					t.Fatal("API key acquired factor evidence")
				}
			} else if result.Authenticated || result.AccessToken != "" {
				t.Fatal("denied policy issued a token")
			}
			if len(response.header.Values("Set-Cookie")) != 0 {
				t.Fatal("API-key exchange established a browser session")
			}
		})
	}
}
