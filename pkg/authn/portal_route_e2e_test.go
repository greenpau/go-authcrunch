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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
)

// Several owners share words in their paths. Exercise the actual consumer so
// mount extraction alone cannot hide a request dispatched to the wrong owner.
func TestE2EPortalReservedRouteOwnership(t *testing.T) {
	for _, mount := range []string{"", "/auth", "/xauth", "/tenant/security", "/saml-service"} {
		t.Run(mount, func(t *testing.T) {
			f := newOIDCE2EFixtureWithPortalConfig(t, mount, true, nil, nil, func(c *authn.PortalConfig) {
				if mount == "" {
					c.RefreshTokens.BasePath = "/"
				}
			})
			page := f.request(t, http.MethodGet, "/login", nil, nil)
			oidcE2EStatus(t, page, http.StatusOK)
			if !strings.HasPrefix(page.header.Get("Content-Type"), "text/html") {
				t.Fatal("login did not reach the browser handler")
			}
			script := f.request(t, http.MethodGet, "/assets/js/login.js", nil, nil)
			oidcE2EStatus(t, script, http.StatusOK)
			if !strings.Contains(script.header.Get("Content-Type"), "javascript") {
				t.Fatal("static resource was dispatched as a login page")
			}
			discovery := f.request(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
			oidcE2EStatus(t, discovery, http.StatusOK)
			var metadata struct {
				Issuer string `json:"issuer"`
			}
			if json.Unmarshal(discovery.body, &metadata) != nil || metadata.Issuer != f.issuer {
				t.Fatal("discovery lost the configured issuer mount")
			}
			// API route ownership wins over the leaf name and HTML negotiation.
			// An accidental dispatch to browser logout would destroy the session.
			checkAPI := func() {
				t.Helper()
				for _, endpoint := range []string{"/api/logout", "/api/refresh_token", "/api/refresh_session"} {
					response := f.request(t, http.MethodGet, endpoint, nil, http.Header{"Accept": {"text/html"}})
					oidcE2EStatus(t, response, http.StatusMethodNotAllowed)
					if response.header.Get("Allow") != http.MethodPost || response.header.Get("Location") != "" || !strings.HasPrefix(response.header.Get("Content-Type"), "application/json") {
						t.Fatalf("%s did not retain the API method/response contract", endpoint)
					}
					if len(response.header.Values("Set-Cookie")) != 0 {
						t.Fatalf("%s changed cookies while rejecting the method", endpoint)
					}
				}
			}
			checkAPI()
			completed := f.loginBrowser(t)
			cookiePath := mount
			if cookiePath == "" {
				cookiePath = "/"
			}
			found := false
			for _, c := range (&http.Response{Header: completed.header}).Cookies() {
				// Login also expires legacy cookies at other paths; check issuance.
				if c.Name == "AUTHP_REFRESH_TOKEN" && c.MaxAge > 0 {
					found = true
					if c.Path != cookiePath {
						t.Fatal("login issued a refresh cookie outside the portal mount")
					}
				}
			}
			if !found {
				t.Fatal("real password login did not issue refresh credentials")
			}
			type identity struct {
				Subject   string `json:"sub"`
				Email     string `json:"email"`
				Origin    string `json:"origin"`
				SessionID string `json:"sid"`
			}
			readIdentity := func() identity {
				t.Helper()
				whoami := f.request(t, http.MethodGet, "/whoami?format=json", nil, nil)
				oidcE2EStatus(t, whoami, http.StatusOK)
				var claims identity
				if err := json.Unmarshal(whoami.body, &claims); err != nil {
					t.Fatal("identity probe did not return JSON claims")
				}
				if claims.Subject != "alice" || claims.Email != "alice@example.test" || claims.Origin != "local" || claims.SessionID == "" {
					t.Fatal("identity probe did not return the logged-in local account and session")
				}
				return claims
			}
			before := readIdentity()
			checkAPI()
			if after := readIdentity(); after != before {
				t.Fatal("API method rejection changed the authenticated identity or session")
			}
		})
	}
}
