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
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestE2EStaticAssetsKeepTokenThePortalDoesNotAdmit(t *testing.T) {
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run(mount, func(t *testing.T) {
			const accessName = "oauth_portal_token"
			issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
			portal := newOIDCE2EPortal(t, issuer, mount, "HS512", "discovery", oidcE2ETrustConfig{gatekeeperCookies: []string{accessName}})
			token, headers := portal.login(t, http.StatusSeeOther)
			client := *portal.client
			var err error
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			origin, err := url.Parse(portal.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client.Jar.SetCookies(origin, (&http.Response{Header: headers}).Cookies())
			access := func() string {
				for _, cookie := range client.Jar.Cookies(origin) {
					if cookie.Name == accessName {
						return cookie.Value
					}
				}
				return ""
			}
			if token == "" || access() != token {
				t.Fatal("real OAuth login did not establish its browser access cookie")
			}
			for _, asset := range []struct {
				path string
				code int
			}{
				{"/favicon.ico", http.StatusNotFound},
				{"/favicon.svg", http.StatusOK},
				{"/assets/images/favicon.svg", http.StatusOK},
			} {
				response := oauthStateRequest(t, &client, portal.server.URL+mount+asset.path)
				if response.StatusCode != asset.code {
					t.Fatalf("asset %s returned HTTP %d, want %d", asset.path, response.StatusCode, asset.code)
				}
				for _, cookie := range response.Cookies() {
					if cookie.Name == accessName {
						t.Fatal("background asset changed a resource-valid access cookie")
					}
				}
				if access() != token {
					t.Fatal("background asset changed the browser's authenticated identity")
				}
				if protected := oauthStateRequest(t, &client, portal.server.URL+"/protected"); protected.StatusCode != http.StatusOK {
					t.Fatalf("resource cookie lost authorization after asset: HTTP %d", protected.StatusCode)
				}
			}
			// Explicit portal admission keeps its established rejection/deletion
			// behavior; preserving an asset cookie does not grant portal access.
			whoami := loginElsewhereProbe(t, &client, portal.server.URL+mount+"/whoami")
			if whoami.StatusCode != http.StatusUnauthorized || access() != "" {
				t.Fatal("ordinary whoami no longer rejects and clears an unadmitted token")
			}
		})
	}
}
