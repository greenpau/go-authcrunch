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
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

// Exercise origin-form targets over TLS: URL.Path is decoded by net/http before
// inferred mounts feed login pages, redirects, cookies and embedded applications.
func TestE2EPortalAmbiguousPathPrefixes(t *testing.T) {
	f, _, _ := newLoginIdentityE2E(t, false, true, false, "")
	anonymous := *f.client
	anonymous.Jar = nil
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/login", nil, nil), http.StatusOK)
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/profile/info", nil, nil), http.StatusOK)
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil), http.StatusOK)
	issuer, err := url.Parse(f.issuer + "/")
	if err != nil {
		t.Fatal(err)
	}
	credentials := f.client.Jar.Cookies(issuer)
	if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") == "" {
		t.Fatal("real login did not establish access credentials")
	}
	for _, prefix := range []string{"//outside.example", "/%2Foutside.example", "/%2foutside.example", `/\outside.example`, "/%5Coutside.example", "/%5coutside.example"} {
		for _, endpoint := range []string{"/login", "/profile", "/portal", "/api/profile", "/basic/login/local", "/.well-known/openid-configuration", "/.well-known/jwks.json", "/oidc/authorize", "/unknown"} {
			for _, authenticated := range []bool{false, true} {
				t.Run(prefix+endpoint+map[bool]string{false: "/anonymous", true: "/authenticated"}[authenticated], func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+prefix+endpoint, nil)
					if err != nil {
						t.Fatal(err)
					}
					if prefix == `/\outside.example` {
						// Opaque preserves the literal backslash in RequestURI; the
						// normal URL encoder would turn this case into another %5C.
						req.URL.Opaque = prefix + endpoint
					}
					if req.URL.RequestURI() != prefix+endpoint {
						t.Fatal("client changed the adversarial request target")
					}
					if authenticated {
						// Send real login credentials independently of jar path matching:
						// malformed targets lie outside the normal /auth cookie path.
						for _, credential := range credentials {
							req.AddCookie(credential)
						}
					}
					response, err := anonymous.Do(req)
					if err != nil {
						t.Fatal("ambiguous path request failed")
					}
					defer response.Body.Close()
					if _, err := io.Copy(io.Discard, response.Body); err != nil {
						t.Fatal("read ambiguous path response")
					}
					if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
						t.Fatal("missing verified TLS")
					}
					if response.StatusCode != http.StatusBadRequest {
						t.Fatalf("ambiguous path HTTP %d, want 400", response.StatusCode)
					}
					if response.Header.Get("Location") != "" || len(response.Cookies()) != 0 || response.Header.Get("Cache-Control") != "no-store" {
						t.Fatal("ambiguous path issued navigation or cookies, or omitted no-store")
					}
				})
			}
		}
	}
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/profile/info", nil, nil), http.StatusOK)
}
