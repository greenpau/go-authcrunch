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

package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestExtractBasePathCookieMount(t *testing.T) {
	factory, err := cookie.NewFactory(&cookie.Config{SandboxIDCookieName: "__Host-SANDBOX"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{"", "/auth", "/tenant/auth", "/tenant%20name/auth"} {
		for _, endpoint := range []string{
			"/login", "/portal", "/logout", "/whoami", "/beacon?format=json",
			"/api/refresh_token", "/api/refresh_session", "/api/logout",
			"/api/profile", "/api/profile/ssh", "/api/server/metadata",
			"/qrcode/login", "/favicon.ico", "/assets/css/style.css",
			"/profile/settings", "/apps/sso", "/apps/mobile-access",
			"/barcode/mfa/c3ludGhldGlj.png", "/sandbox/session",
			"/register", "/register/ack/id", "/basic/login/local",
			"/oauth2/provider/logout", "/saml/provider", "/recover", "/forgot",
			"/oauth2/beacon", "/saml/beacon", "/basic/login/beacon",
			"/apps/sso/beacon", "/barcode/mfa/beacon", "/assets/beacon",
		} {
			t.Run(mount+endpoint, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "https://example.test"+mount+endpoint, nil)
				rr := requests.NewRequest()
				extractBasePath(t.Context(), r, rr)
				if rr.Upstream.BasePath != mount+"/" || rr.Upstream.BaseURL != "https://example.test" {
					t.Fatalf("Path=%q RawPath=%q RequestURI=%q: base path %q, URL %q", r.URL.Path, r.URL.RawPath, r.RequestURI, rr.Upstream.BasePath, rr.Upstream.BaseURL)
				}
				if err := factory.ValidatePortalPath(rr.Upstream.BasePath); (err == nil) != (mount == "") {
					t.Fatalf("Path=%q: host cookie mount validation: %v", r.URL.Path, err)
				}
			})
		}
	}
}
