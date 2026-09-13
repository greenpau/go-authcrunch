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
	"net/http"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// The fixture imports the shared public directive parser, persists/reloads its
// result, and constructs the real provider, portal, and gatekeeper. Each case
// uses fresh TLS listeners and browser state so authentication caches cannot
// hide a missing trust check. Both supported Ed25519 method names are exercised.
func TestE2EOAuthIdentityProviderDirectives(t *testing.T) {
	for _, algorithm := range []string{"EdDSA", "Ed25519"} {
		for _, tc := range []struct {
			name, mode, failure, issuer, audience string
			denied, editor                        bool
		}{
			{name: "explicit trust", mode: "discovery", issuer: "actual", audience: "resource-api", editor: true},
			{name: "discovered issuer", mode: "discovery", audience: "resource-api", editor: true},
			{name: "explicit issuer mismatch", mode: "discovery", issuer: "https://wrong.example", audience: "resource-api", denied: true},
			{name: "exact issuer trailing slash", mode: "discovery", issuer: "trailing slash", audience: "resource-api", denied: true},
			{name: "explicit issuer overrides discovery", mode: "discovery", failure: "discovery issuer", issuer: "actual", audience: "resource-api", editor: true},
			{name: "discovery issuer enforced", mode: "discovery", failure: "discovery issuer", audience: "resource-api", denied: true},
			{name: "static explicit trust", mode: "static", issuer: "actual", audience: "resource-api", editor: true},
			{name: "static issuer mismatch", mode: "static", issuer: "https://wrong.example", audience: "resource-api", denied: true},
			{name: "static issuer omission preserves optional check", mode: "static", failure: "issuer", audience: "resource-api", editor: true},
			{name: "access audience mismatch omits access claims", mode: "discovery", issuer: "actual", audience: "other-resource"},
			{name: "explicit access audience does not fall back to azp", mode: "discovery", issuer: "actual", audience: oidcE2EClientID},
			{name: "omitted access audience retains azp fallback", mode: "discovery", issuer: "actual", editor: true},
			{name: "access issuer mismatch omits access claims", mode: "discovery", failure: "access issuer", issuer: "actual", audience: "resource-api"},
			{name: "ID audience remains client ID", mode: "discovery", failure: "audience", issuer: "actual", audience: "wrong-client", denied: true},
		} {
			t.Run(algorithm+"/"+tc.name, func(t *testing.T) {
				issuer := newOIDCE2EIssuer(t, algorithm, "jwt", tc.failure, false)
				expectedIssuer := tc.issuer
				switch expectedIssuer {
				case "actual":
					expectedIssuer = issuer.server.URL
				case "trailing slash":
					expectedIssuer = issuer.server.URL + "/"
				}
				portal := newOIDCE2EPortal(t, issuer, "/tenant/auth", "HS512", tc.mode, oidcE2ETrustConfig{issuer: expectedIssuer, audience: tc.audience})
				wantStatus := http.StatusSeeOther
				if tc.denied {
					wantStatus = http.StatusUnauthorized
				}
				token, _ := portal.login(t, wantStatus)
				status, body := portal.get(t, "/protected", token)
				if tc.denied {
					if status == http.StatusOK || string(body) == "protected-resource" {
						t.Fatal("rejected identity obtained protected access")
					}
					return
				}
				if status != http.StatusOK || string(body) != "protected-resource" {
					t.Fatal("accepted identity could not access the protected resource")
				}
				parsed, err := jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return []byte(oidcE2EPortalSecret), nil }, jwtlib.WithValidMethods([]string{"HS512"}))
				if err != nil || !parsed.Valid {
					t.Fatal("independent portal token verification failed")
				}
				roles, ok := parsed.Claims.(jwtlib.MapClaims)["roles"].([]any)
				if !ok {
					t.Fatal("portal token omitted upstream roles")
				}
				var editor, viewer bool
				for _, role := range roles {
					editor = editor || role == "editor"
					viewer = viewer || role == "viewer"
				}
				if editor != tc.editor || (!tc.editor && !viewer) {
					t.Fatal("portal roles did not respect configured optional access-token trust")
				}
				issuer.mu.Lock()
				metadata, keys, exchanges := issuer.metadataFetches, issuer.keyFetches, issuer.exchanges
				issuer.mu.Unlock()
				if exchanges != 1 {
					t.Fatal("expected one real authorization code exchange")
				}
				if tc.mode == "static" && (metadata != 0 || keys != 0) {
					t.Fatal("static public-key directives unexpectedly used discovery")
				}
			})
		}
	}
}
