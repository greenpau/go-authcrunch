// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"bytes"
	"encoding/json"
	"html/template"
	"strings"
	"testing"
)

func TestNewFactory(t *testing.T) {
	t.Log("Creating UI factory")
	f := NewFactory()
	f.Title = "Authentication"
	f.LogoURL = "/images/logo.png"
	f.LogoDescription = "Authentication Portal"
	officeLink := Link{
		Title: "Office 365",
		Link:  "https://office.com/",
		Style: "fa-windows",
	}
	f.PublicLinks = append(f.PublicLinks, officeLink)
	f.PrivateLinks = append(f.PrivateLinks, Link{
		Title: "Prometheus",
		Link:  "/prometheus",
	})
	f.PrivateLinks = append(f.PrivateLinks, Link{
		Title: "Alertmanager",
		Link:  "/alertmanager",
	})
	f.ActionEndpoint = "/auth/login"

	t.Log("Adding a built-in template")
	if err := f.AddBuiltinTemplate("basic/login"); err != nil {
		t.Fatalf("Expected success, but got error: %s, %v", err, f.Templates)
	}

	t.Log("Adding a template from file system")
	if err := f.AddTemplate("login", "../../../assets/portal/templates/basic/login.template"); err != nil {
		t.Fatalf("Expected success, but got error: %s, %v", err, f.Templates)
	}

	loginRealm := make(map[string]string)
	loginRealm["realm"] = "local"
	loginRealm["label"] = strings.ToTitle("Local")
	loginRealm["default"] = "yes"

	var loginRealms []map[string]string
	loginRealms = append(loginRealms, loginRealm)

	loginOptions := make(map[string]interface{})
	loginOptions["form_required"] = "yes"
	loginOptions["realm_dropdown_required"] = "no"
	loginOptions["identity_required"] = "yes"
	loginOptions["realms"] = loginRealms
	loginOptions["default_realm"] = "local"
	loginOptions["authenticators"] = []map[string]interface{}{
		map[string]interface{}{
			"background_color":          "#324960",
			"class_name":                "las la-key la-2x",
			"color":                     "white",
			"password_recovery_enabled": "y",
			"realm":                     "local",
			"text":                      "LOCAL",
			"text_color":                "#37474f",
		},
	}

	uiOptions := make(map[string]interface{})
	uiOptions["custom_css_required"] = "no"
	uiOptions["custom_js_required"] = "no"

	t.Log("Rendering templates")
	args := f.GetArgs()
	args.Data["login_options"] = loginOptions
	args.Data["ui_options"] = uiOptions

	var t1, t2 *bytes.Buffer
	var err error
	if t1, err = f.Render("basic/login", args); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}

	args = f.GetArgs()
	args.Data["login_options"] = loginOptions
	args.Data["ui_options"] = uiOptions
	if t2, err = f.Render("login", args); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}
	if strings.TrimSpace(t1.String()) != strings.TrimSpace(t2.String()) {
		t.Fatalf("Expected templates to match, but got mismatch: %d (basic/login) vs. %d (login)", t1.Len(), t2.Len())
	}

}

func TestHTMLTemplateEscaping(t *testing.T) {
	t.Log("Testing html/template escaping behavior")

	webauthnArgs := &Args{Data: map[string]interface{}{}}
	webauthnJSON, _ := json.Marshal(map[string]interface{}{
		"challenge": "abc123",
		"timeout":   60000,
		"ext_uvm":   false,
	})
	webauthnArgs.Data["webauthn_params"] = template.JS(webauthnJSON)

	testcases := []struct {
		name     string
		template string
		args     *Args
		contains []string
		excludes []string
	}{
		{
			name:     "message with special chars is HTML-escaped in toast div",
			template: `{{ if .Message }}<div id="toast-msg" style="display:none"><span>{{ .Message }}</span></div>{{ end }}`,
			args:     &Args{Message: `<script>alert("xss")</script>`},
			contains: []string{`&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;`},
			excludes: []string{`<script>alert`},
		},
		{
			name:     "webauthn params rendered as raw JS from template.JS",
			template: `<script>const p = {{ .Data.webauthn_params }};</script>`,
			args:     webauthnArgs,
			contains: []string{`"challenge":"abc123"`, `"timeout":60000`, `"ext_uvm":false`},
		},
		{
			name:     "brsplitline produces unescaped br tags",
			template: `<div>{{ "abcdefghijklmnopqrstuvwxyz1234567890" | brsplitline }}</div>`,
			args:     &Args{},
			contains: []string{`<br>`},
			excludes: []string{`&lt;br&gt;`},
		},
		{
			name:     "webauthn params with script tag in value are neutralized by json.Marshal",
			template: `<script>const p = {{ .Data.webauthn_params }};</script>`,
			args: func() *Args {
				a := &Args{Data: map[string]interface{}{}}
				b, _ := json.Marshal(map[string]interface{}{
					"challenge": `</script><script>alert("xss")</script>`,
				})
				a.Data["webauthn_params"] = template.JS(b)
				return a
			}(),
			contains: []string{`\u003c/script\u003e`},
			excludes: []string{`</script><script>alert`},
		},
		{
			name:     "pathjoin in script src is not broken",
			template: `<script src="{{ pathjoin .ActionEndpoint "/assets/js/app.js" }}"></script>`,
			args:     &Args{ActionEndpoint: "/auth"},
			contains: []string{`src="/auth/assets/js/app.js"`},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Parsing template: %s", tc.name)
			tmpl, err := loadTemplateFromString("test", tc.template)
			if err != nil {
				t.Fatalf("Expected success, but got error: %v", err)
			}
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, tc.args); err != nil {
				t.Fatalf("Expected success, but got error: %v", err)
			}
			output := buf.String()
			for _, s := range tc.contains {
				if !strings.Contains(output, s) {
					t.Errorf("Expected output to contain %q, got: %s", s, output)
				}
			}
			for _, s := range tc.excludes {
				if strings.Contains(output, s) {
					t.Errorf("Expected output NOT to contain %q, got: %s", s, output)
				}
			}
		})
	}
}

func TestAddBuiltinTemplates(t *testing.T) {
	var expError string
	t.Logf("Creating UI factory")
	f := NewFactory()

	t.Logf("Adding templates")
	if err := f.AddBuiltinTemplates(); err != nil {
		t.Fatal(err)
	}

	if err := f.AddBuiltinTemplate("saml"); err != nil {
		expError = "built-in template saml does not exists"
		if err.Error() != expError {
			t.Fatalf("Mismatch between errors: %s (received) vs. %s (expected)", err.Error(), expError)
		}
	} else {
		t.Fatalf("Expected an error, but got success")
	}

	t.Logf("Purging templates")
	f.DeleteTemplates()

	t.Logf("Re-adding templates")
	if err := f.AddBuiltinTemplate("basic/login"); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}

	t.Logf("Purging templates")
	f.DeleteTemplates()

	t.Logf("Re-adding templates")
	if err := f.AddBuiltinTemplate("basic/login"); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}

	t.Logf("Purging templates")
	f.DeleteTemplates()

	t.Logf("Re-adding templates")
	if err := f.AddBuiltinTemplate("basic/portal"); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}
}
