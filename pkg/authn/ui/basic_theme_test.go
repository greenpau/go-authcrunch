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

package ui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func TestBasicThemeBrandAssets(t *testing.T) {
	core, err := NewStaticAssetLibrary()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewAppAssetLibrary()
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct{ core, profile string }{
		{"assets/images/logo.svg", "profile/logo.svg"},
		{"assets/images/favicon.svg", "profile/favicon.svg"},
		{"assets/images/banner.svg", "profile/images/banner.svg"},
	} {
		t.Run(pair.core, func(t *testing.T) {
			portalAsset, err := core.GetAsset(pair.core)
			if err != nil {
				t.Fatal(err)
			}
			profileAsset, err := profile.GetAsset(pair.profile)
			if err != nil {
				t.Fatal(err)
			}
			if portalAsset.ContentType != "image/svg+xml" || profileAsset.ContentType != "image/svg+xml" || portalAsset.Content != profileAsset.Content {
				t.Fatal("portal and profile must serve matching SVG branding")
			}
		})
	}
	for _, library := range []*StaticAssetLibrary{core, profile} {
		for _, path := range library.GetAssetPaths() {
			if strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".ico") {
				t.Errorf("legacy raster asset remains: %s", path)
			}
		}
	}
	manifestAsset, err := profile.GetAsset("profile/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Icons []struct {
			Src  string `json:"src"`
			Type string `json:"type"`
		} `json:"icons"`
	}
	if err := json.Unmarshal([]byte(manifestAsset.Content), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Icons) == 0 {
		t.Fatal("profile manifest is missing its SVG icon")
	}
	for _, icon := range manifest.Icons {
		asset, err := profile.GetAsset("profile/" + icon.Src)
		if err != nil {
			t.Fatal(err)
		}
		if icon.Type != "image/svg+xml" || asset.ContentType != icon.Type {
			t.Fatal("profile manifest icon must resolve to a registered SVG")
		}
	}
}

// Every view must retain its branding, mounted assets, and final CSS override.
// Browser E2E verifies the computed styles and real form/session behavior.
func TestBasicTheme(t *testing.T) {
	cases := map[string][]string{
		"login": {"single", "multiple"}, "portal": {"portal"}, "generic": {"generic"},
		"whoami": {"whoami"}, "apps_sso": {"apps_sso"}, "apps_mobile_access": {"apps_mobile_access"},
		"session": {"continue", "logout"}, "oidc": {"consent", "form_post", "error"},
		"register": {"register", "registered", "ack", "ackfail", "acked"},
		"sandbox":  {"mfa_mixed_auth", "mfa_mixed_register", "password_auth", "password_recovery", "mfa_app_auth", "mfa_app_register", "mfa_u2f_auth", "mfa_u2f_register", "terminate", "error"},
	}
	for _, mount := range []string{"", "/tenant/auth"} {
		for _, custom := range []bool{false, true} {
			f := NewFactory()
			f.MetaTitle = "Example <Brand>"
			f.LogoURL = "/assets/images/brand.svg"
			f.LogoDescription = "Example <Logo>"
			if custom {
				f.CustomCSSPath = "theme.css"
			}
			if err := f.AddBuiltinTemplates(); err != nil {
				t.Fatal(err)
			}
			for alias, views := range cases {
				if err := f.AddTemplate(alias, "page_templates/basic/"+alias+".template"); err != nil {
					t.Fatal(err)
				}
				for _, view := range views {
					t.Run(mount+"/"+alias+"/"+view+"/custom="+map[bool]string{true: "yes", false: "no"}[custom], func(t *testing.T) {
						args := f.GetArgs()
						args.BaseURL(mount)
						args.PageTitle = "Example <Heading>"
						args.Message = "Example <Message>"
						args.Data["view"] = view
						args.Data["session_action"] = view
						args.Data["session_next"] = mount + "/login"
						args.Data["message"] = "Example <Message>"
						args.Data["id"] = "fixture-id"
						args.Data["registration_realm_name"] = "local"
						args.Data["registration_id"] = "fixture-registration"
						args.Data["code_uri_encoded"] = "fixture-qr"
						args.Data["role_count"] = 0
						args.Data["login_options"] = map[string]any{"authenticators": []any{}, "form_required": "no"}
						if alias == "login" {
							args.Data["i18n_provide_username_or_email"] = "Username or email"
							options := map[string]any{
								"authenticators": []map[string]string{{"realm": "local", "text": "Local"}},
								"realms":         []map[string]string{{"realm": "local", "default": "yes"}},
								"form_required":  "yes",
								"default_realm":  "local",
							}
							if view == "multiple" {
								options["authenticators_required"] = "yes"
								options["authenticators"] = []map[string]string{
									{"realm": "local", "text": "Local"},
									{"endpoint": "/external-login", "text": "External <Provider>"},
								}
							}
							args.Data["login_options"] = options
						}
						args.Data["oidc"] = oidc.Page{Kind: view, Title: args.PageTitle, Message: args.Message, Action: "https://example.test/callback", Nonce: "fixture-nonce"}
						embedded, err := f.Render("basic/"+alias, args)
						if err != nil {
							t.Fatal(err)
						}
						filesystem, err := f.Render(alias, args)
						if err != nil {
							t.Fatal(err)
						}
						if embedded.String() != filesystem.String() {
							t.Fatal("filesystem override differs from embedded view")
						}
						body := embedded.String()
						if alias == "login" {
							for _, expected := range []string{`action="` + mount + `/login" method="POST"`, `for="username"`, `name="username"`, `name="realm" value="local"`, "Username or email"} {
								if !strings.Contains(body, expected) {
									t.Errorf("login form lost %q", expected)
								}
							}
							if view == "multiple" {
								for _, expected := range []string{`id="loginform" class="hidden"`, `onclick="showLoginForm(`, `onclick="hideLoginForm();`, `href="/external-login"`, "External &lt;Provider&gt;"} {
									if !strings.Contains(body, expected) {
										t.Errorf("realm selection lost %q", expected)
									}
								}
							} else if strings.Contains(body, `id="loginform" class="hidden"`) || strings.Contains(body, `id="authenticators"`) {
								t.Fatal("single realm must display the login form directly")
							}
						}
						if strings.Count(body, `rel="icon"`) != 1 || strings.Contains(body, "favicon.png") || strings.Contains(body, "favicon.ico") {
							t.Fatal("page must use only the SVG favicon")
						}
						for _, expected := range []string{"basic-theme", "brand-banner", "Example &lt;Brand&gt;", "Example &lt;Heading&gt;", "Example &lt;Logo&gt;", `src="` + mount + `/assets/images/brand.svg"`, `href="` + mount + `/assets/images/favicon.svg"`, `href="` + mount + `/assets/css/basic.css"`} {
							if !strings.Contains(body, expected) {
								t.Errorf("missing brand feature %q", expected)
							}
						}
						if strings.Contains(body, "ZgotmplZ") || strings.Contains(body, "<Brand>") {
							t.Fatal("invalid escaping")
						}
						customIndex := strings.Index(body, "/assets/css/custom.css")
						if (customIndex >= 0) != custom {
							t.Fatal("custom CSS hook does not follow configuration")
						}
						if custom && strings.Contains(body[customIndex+len("/assets/css/custom.css"):strings.Index(body, "</head>")], `rel="stylesheet"`) {
							t.Fatal("base stylesheet overrides custom CSS")
						}
						if alias == "session" {
							if !strings.Contains(body, `id="session-message"`) || !strings.Contains(body, `/login?fresh=1`) || !strings.Contains(body, `data-base="`+mount+`"`) || !strings.Contains(body, `data-action="`+view+`"`) {
								t.Fatal("session DOM contract changed")
							}
							if strings.Contains(body, `id="session-logout"`) != (view == "logout") {
								t.Fatal("logout confirmation conditional changed")
							}
							if strings.Contains(body, "<style") || strings.Contains(body, "onclick=") || strings.Contains(body, "<script>") {
								t.Fatal("session includes inline resources blocked by CSP")
							}
						}
					})
				}
			}
		}
	}
}
