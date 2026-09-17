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
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func TestOIDCTemplate(t *testing.T) {
	f := NewFactory()
	f.MetaTitle = "Example <Portal>"
	f.CustomCSSPath = "theme.css"
	if err := f.AddBuiltinTemplate("basic/oidc"); err != nil {
		t.Fatal(err)
	}
	if err := f.AddTemplate("custom-oidc", "page_templates/basic/oidc.template"); err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{"", "/tenant/auth"} {
		for _, kind := range []string{"consent", "form_post", "error"} {
			t.Run(mount+"/"+kind, func(t *testing.T) {
				args := f.GetArgs()
				args.BaseURL(mount)
				args.PageTitle = "Test page"
				page := oidc.Page{Kind: kind, Title: "Test page", ClientName: `<script>evil()</script>`, Username: `<img src=x>`, Action: "https://example.test/callback", CSRF: `csrf"<&`, Nonce: "test-nonce", Message: "Return to the application.", Permissions: []oidc.PagePermission{{Title: "Account identifier", Description: "Recognize your account."}}, UserInfoClaims: []string{"Full name"}, IDTokenClaims: []string{"Given name"}, Values: url.Values{"state": {`</script><script>evil()</script>`}, "code": {"synthetic-code"}}}
				args.Data["oidc"] = page
				embedded, err := f.Render("basic/oidc", args)
				if err != nil {
					t.Fatal(err)
				}
				custom, err := f.Render("custom-oidc", args)
				if err != nil {
					t.Fatal(err)
				}
				if embedded.String() != custom.String() {
					t.Fatal("filesystem template differs from embedded template")
				}
				body := embedded.String()
				for _, expected := range []string{`href="` + mount + `/assets/css/oidc.css"`, `href="` + mount + `/assets/css/custom.css"`, `src="` + mount + `/assets/images/logo.svg"`, "Example &lt;Portal&gt;", `aria-labelledby="oidc-title"`} {
					if !strings.Contains(body, expected) {
						t.Errorf("missing page feature %q", expected)
					}
				}
				if strings.Contains(body, "<script>evil()") || strings.Contains(body, "<img src=x>") || strings.Contains(body, "ZgotmplZ") {
					t.Fatal("unsafe template escaping")
				}
				if strings.Index(body, "oidc.css") > strings.Index(body, "custom.css") {
					t.Fatal("custom stylesheet cannot override defaults")
				}
				switch kind {
				case "consent":
					if !strings.Contains(body, "Additional information") || !strings.Contains(body, "Included when you sign in") || strings.Contains(body, "<script") {
						t.Fatal("consent content or script policy changed")
					}
				case "form_post":
					if !strings.Contains(body, `nonce="test-nonce"`) || !strings.Contains(body, "synthetic-code") || !strings.Contains(body, "<noscript>") {
						t.Fatal("form-post fallback missing")
					}
				case "error":
					if !strings.Contains(body, page.Message) || strings.Contains(body, "<form") || strings.Contains(body, "<script") {
						t.Fatal("error page exposes an action")
					}
				}
			})
		}
	}
}
