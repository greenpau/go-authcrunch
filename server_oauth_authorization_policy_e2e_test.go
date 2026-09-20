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

package authcrunch_test

import (
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz"
)

func TestE2EServerDirectOAuthRechecksSourceAddress(t *testing.T) {
	f := newDirectOAuthFixtureWithPolicy(t, func(p *authz.PolicyConfig) {
		p.ValidateSourceAddress = true
	})
	// These headers model client-IP metadata already normalized by the embedding
	// server. Trust and stripping of forwarded headers remain that server's job.
	address := http.Header{"X-Real-Ip": {"192.0.2.10"}}
	callback := f.callback(t, f.client, "/private/report")
	directOAuthStatus(t, f.request(t, f.client, http.MethodGet, callback, address), http.StatusSeeOther)
	for range 2 {
		directOAuthStatus(t, f.request(t, f.client, http.MethodGet, "/private/report", address), http.StatusOK)
	}
	directOAuthStatus(t, f.request(t, f.client, http.MethodGet, "/private/report", http.Header{"X-Real-Ip": {"192.0.2.11"}}), http.StatusForbidden)
	for _, target := range []string{"/admin/report", "/private/../admin/report", "/private/%252e%252e/admin/report", "/private%2freport"} {
		directOAuthStatus(t, f.request(t, f.client, http.MethodGet, target, address), http.StatusForbidden)
	}
	// Denials cannot corrupt the stored identity or evict a still-valid session.
	directOAuthStatus(t, f.request(t, f.client, http.MethodGet, "/private/report", address), http.StatusOK)
	if f.exchanges.Load() != 1 {
		t.Fatal("session policy checks unexpectedly repeated the token exchange")
	}

}

func TestE2EServerDirectOAuthRequiresEffectivePathClaims(t *testing.T) {
	f := newDirectOAuthFixtureWithPolicy(t, func(p *authz.PolicyConfig) {
		p.ValidateAccessListPathClaim = true
	})
	for _, mode := range []string{"", "path claims"} {
		f.mu.Lock()
		f.failure = mode
		f.mu.Unlock()
		f.client.Jar, _ = cookiejar.New(nil)
		// Generic OAuth's identity mapping does not forward arbitrary acl claims.
		// An assertion containing them is still not an effective path grant.
		callback := f.callback(t, f.client, "/private/report")
		denied := f.request(t, f.client, http.MethodGet, callback, nil)
		directOAuthStatus(t, denied, http.StatusForbidden)
		for _, cookie := range denied.cookies {
			if cookie.Name == "AUTHZ_primary_SESSION" && cookie.MaxAge >= 0 {
				t.Fatal("path-denied callback issued a session")
			}
		}
	}
}
