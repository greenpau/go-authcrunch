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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestE2EOAuthBeaconRealmCookieMount(t *testing.T) {
	for _, tc := range []struct{ name, mount, sandboxCookie string }{
		{name: "root"},
		{name: "root host cookie", sandboxCookie: "__Host-SANDBOX"},
		{name: "nested", mount: "/tenant/auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
			portal := newOIDCE2EPortal(t, issuer, tc.mount, "HS512", "discovery", oidcE2ETrustConfig{realm: "beacon", sandboxCookie: tc.sandboxCookie})
			if status, _ := portal.get(t, "/protected", ""); status != http.StatusFound {
				t.Fatalf("unauthenticated resource returned HTTP %d", status)
			}
			token, _ := portal.login(t, http.StatusSeeOther)
			if token == "" {
				t.Fatal("OAuth login omitted the portal token")
			}
			if status, body := portal.get(t, "/protected", token); status != http.StatusOK || string(body) != "protected-resource" {
				t.Fatalf("authenticated resource returned HTTP %d, matching body %t", status, string(body) == "protected-resource")
			}
		})
	}
}

func TestE2EOAuthIdentityCookieNames(t *testing.T) {
	for _, tc := range []struct{ setting, name string }{{"default", "AUTHP_ID_TOKEN"}, {"UPSTREAM_IDENTITY", "UPSTREAM_IDENTITY"}, {"__Secure-UPSTREAM_IDENTITY", "__Secure-UPSTREAM_IDENTITY"}} {
		t.Run(tc.setting, func(t *testing.T) {
			issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
			portal := newOIDCE2EPortal(t, issuer, "/auth", "HS512", "discovery", oidcE2ETrustConfig{identityCookie: tc.setting})
			_, headers := portal.login(t, http.StatusSeeOther)
			var identityCookie *http.Cookie
			for _, c := range (&http.Response{Header: headers}).Cookies() {
				if c.Name == tc.name {
					identityCookie = c
				}
				if c.Name == "ID_TOKEN" {
					t.Fatal("provider emitted a bare cookie suffix")
				}
			}
			if identityCookie == nil || !identityCookie.Secure || !identityCookie.HttpOnly || identityCookie.Path != "/auth/whoami" {
				t.Fatal("identity token cookie did not use its configured name and scope")
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			portal.client.Jar = jar
			origin, err := url.Parse(portal.server.URL + "/auth/login")
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(origin, (&http.Response{Header: headers}).Cookies())
			whoami, err := http.NewRequestWithContext(t.Context(), http.MethodGet, portal.server.URL+"/auth/whoami?id_token=true", nil)
			if err != nil {
				t.Fatal(err)
			}
			whoami.Header.Set("Accept", "application/json")
			whoami.Header.Set("Content-Type", "application/json")
			identity, err := portal.client.Do(whoami)
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			decodeErr := json.NewDecoder(io.LimitReader(identity.Body, 1<<20)).Decode(&claims)
			identity.Body.Close()
			if identity.StatusCode != http.StatusOK || decodeErr != nil {
				t.Fatalf("whoami response: HTTP %d, valid JSON %t", identity.StatusCode, decodeErr == nil)
			}
			if claims["id_token"] != identityCookie.Value {
				t.Fatal("whoami did not read the configured identity cookie")
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, portal.server.URL+"/auth/oauth2/upstream/logout", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := portal.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			deleted := false
			for _, c := range response.Cookies() {
				if c.Name == tc.name && c.Path == identityCookie.Path && c.Expires.Year() == 1970 && c.Secure == identityCookie.Secure && c.HttpOnly == identityCookie.HttpOnly && c.Domain == identityCookie.Domain && c.MaxAge == -1 {
					deleted = true
				}
			}
			if !deleted {
				t.Fatal("external logout omitted the configured cookie deletion")
			}
			target, _ := url.Parse(portal.server.URL + "/auth/whoami")
			for _, c := range jar.Cookies(target) {
				if c.Name == tc.name {
					t.Fatal("logout retained the identity token cookie")
				}
			}
		})
	}
}
