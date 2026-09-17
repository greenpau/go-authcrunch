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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
)

func TestE2EOIDCPortalTemplates(t *testing.T) {
	for _, mount := range []string{"", "/tenant/auth"} {
		for _, custom := range []bool{false, true} {
			name := mount + "/builtin"
			if custom {
				name = mount + "/custom"
			}
			t.Run(name, func(t *testing.T) {
				params := &ui.Parameters{MetaTitle: "Example <Portal>", LogoDescription: "Example logo"}
				if custom {
					// Restore the process-global custom asset registry after this fixture.
					original := ui.StaticAssets
					isolated, err := ui.NewStaticAssetLibrary()
					if err != nil {
						t.Fatal(err)
					}
					ui.StaticAssets = isolated
					t.Cleanup(func() { ui.StaticAssets = original })
					template, err := os.ReadFile("ui/page_templates/basic/oidc.template")
					if err != nil {
						t.Fatal(err)
					}
					template = []byte(strings.Replace(string(template), "<head>", `<head><meta name="theme-test" content="custom">`, 1))
					templatePath := filepath.Join(t.TempDir(), "oidc.template")
					if err := os.WriteFile(templatePath, template, 0600); err != nil {
						t.Fatal(err)
					}
					params.Templates = map[string]string{"oidc": templatePath}
					params.CustomCSSPath = filepath.Join(t.TempDir(), "theme.css")
					if err := os.WriteFile(params.CustomCSSPath, []byte(".oidc-page { --oidc-accent: #164c75; }"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				f := newOIDCE2EFixtureWithPortalConfig(t, mount, false, nil, nil, func(c *authn.PortalConfig) { c.UI = params })
				auth := f.authorization("basic")
				start := f.request(t, "GET", "/oidc/authorize?"+auth.Encode(), nil, nil)
				oidcE2EStatus(t, start, 303)
				completed := f.loginBrowser(t)
				consent := f.request(t, "GET", completed.header.Get("Location"), nil, http.Header{"Accept": {"text/html"}})
				oidcE2EStatus(t, consent, 200)
				for _, expected := range []string{"Review requested access", "Example &lt;Portal&gt;", `href="` + mount + `/assets/css/oidc.css"`, `action="` + f.issuer + `/oidc/continue"`} {
					if !strings.Contains(string(consent.body), expected) {
						t.Fatalf("missing themed consent element %q", expected)
					}
				}
				if strings.Contains(string(consent.body), `name="theme-test"`) != custom {
					t.Fatal("filesystem template override ignored")
				}
				for _, asset := range []struct{ path, kind string }{
					{"/assets/css/oidc.css", "text/css"}, {"/assets/google-webfonts/roboto.css", "text/css"},
					{"/assets/images/logo.svg", "image/svg+xml"}, {"/assets/images/favicon.svg", "image/svg+xml"},
					{"/assets/images/banner.svg", "image/svg+xml"}, {"/assets/images/background.svg", "image/svg+xml"},
					{"/favicon.svg", "image/svg+xml"}, {"/profile/favicon.svg", "image/svg+xml"},
					{"/profile/logo.svg", "image/svg+xml"}, {"/profile/images/banner.svg", "image/svg+xml"},
				} {
					response := f.request(t, "GET", asset.path, nil, nil)
					oidcE2EStatus(t, response, 200)
					if !strings.HasPrefix(response.header.Get("Content-Type"), asset.kind) {
						t.Fatal("page asset MIME type incorrect")
					}
				}
				for _, retired := range []string{"/assets/images/favicon.png", "/assets/images/favicon.ico", "/profile/favicon.ico", "/profile/logo192.png", "/profile/logo512.png"} {
					oidcE2EStatus(t, f.request(t, "GET", retired, nil, nil), http.StatusNotFound)
				}
				profile := f.request(t, "GET", "/profile/", nil, nil)
				oidcE2EStatus(t, profile, http.StatusOK)
				if !strings.Contains(string(profile.body), `href="./favicon.svg"`) || strings.Contains(string(profile.body), ".png") {
					t.Fatal("profile page does not use SVG branding")
				}
				if custom {
					css := f.request(t, "GET", "/assets/css/custom.css", nil, nil)
					if css.status != 200 || !strings.Contains(string(css.body), "#164c75") {
						t.Fatal("custom stylesheet not served")
					}
				}
				invalid := f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {"incorrect"}, "decision": {"allow"}}, http.Header{"Origin": {f.server.URL}, "Accept": {"text/html"}})
				oidcE2EStatus(t, invalid, 403)
				if !strings.Contains(string(invalid.body), "Unable to continue") || invalid.header.Get("Location") != "" {
					t.Fatal("invalid consent did not stay on the error page")
				}
				// Correct CSRF cannot authorize a null or foreign browser origin.
				csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(consent.body)
				if len(csrf) != 2 {
					t.Fatal("missing CSRF form field")
				}
				for _, origin := range []string{"null", "https://unregistered.invalid"} {
					rejected := f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {string(csrf[1])}, "decision": {"allow"}}, http.Header{"Origin": {origin}, "Accept": {"text/html"}})
					if rejected.status != 403 || rejected.header.Get("Location") != "" {
						t.Fatal("untrusted origin bypassed consent")
					}
				}
				// A rejected CSRF does not approve or consume the original consent.
				denied := f.approve(t, consent, "deny")
				target, _ := url.Parse(denied.header.Get("Location"))
				if target.Query().Get("error") != "access_denied" || target.Query().Get("code") != "" {
					t.Fatal("Deny granted access")
				}
				consent = f.request(t, "GET", "/oidc/authorize?"+auth.Encode(), nil, nil)
				code := oidcProviderE2ECode(t, f.approve(t, consent, "allow"))
				f.verifyIDToken(t, oidcE2ETokens(t, f.exchange(t, "basic", code, oidcE2EVerifier)), "basic")
				auth.Set("response_mode", "form_post")
				continuation := f.request(t, "GET", "/oidc/authorize?"+auth.Encode(), nil, nil)
				if continuation.status != 200 || !strings.Contains(string(continuation.body), `id="response"`) || !strings.Contains(string(continuation.body), "Example &lt;Portal&gt;") || strings.Contains(string(continuation.body), `name="theme-test"`) != custom {
					t.Fatal("continuation did not use the portal theme")
				}
				errorPage := f.request(t, "GET", "/oidc/continue", nil, http.Header{"Accept": {"text/html"}})
				if errorPage.status != 400 || !strings.Contains(string(errorPage.body), "Unable to continue") || strings.Contains(string(errorPage.body), `name="theme-test"`) != custom {
					t.Fatal("expired continuation did not use the portal theme")
				}
				apiError := f.request(t, "GET", "/oidc/continue", nil, http.Header{"Accept": {"application/json"}})
				if apiError.status != 400 || apiError.header.Get("Content-Type") != "application/json" {
					t.Fatal("API error format changed")
				}
				for _, negotiation := range []struct {
					accept []string
					html   bool
				}{
					{[]string{"application/json;q=0.2", "text/html"}, true},
					{[]string{"text/html;q=0.2", "application/json"}, false},
				} {
					response := f.request(t, "GET", "/oidc/continue", nil, http.Header{"Accept": negotiation.accept})
					if response.status != 400 || strings.HasPrefix(response.header.Get("Content-Type"), "text/html") != negotiation.html || response.header.Get("Vary") != "Accept" {
						t.Fatal("repeated Accept fields lost their negotiated error format")
					}
				}
			})
		}
	}
}

func TestE2EOIDCTemplateExecutionFailure(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "broken.template")
	if err := os.WriteFile(templatePath, []byte(`private-partial-output{{ index .Data.oidc.Permissions 999 }}`), 0600); err != nil {
		t.Fatal(err)
	}
	f := newOIDCE2EFixtureWithPortalConfig(t, "/auth", false, nil, nil, func(c *authn.PortalConfig) {
		c.UI = &ui.Parameters{Templates: map[string]string{"oidc": templatePath}}
	})
	f.loginBrowser(t)
	response := f.request(t, "GET", "/oidc/authorize?"+f.authorization("basic").Encode(), nil, nil)
	if response.status != 500 || strings.TrimSpace(string(response.body)) != `{"error":"server_error"}` || response.header.Get("Location") != "" {
		t.Fatal("template failure leaked partial output or granted access")
	}
}
