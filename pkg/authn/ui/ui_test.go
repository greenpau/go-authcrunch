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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/translate"
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
	if err := f.AddTemplate("login", "../../../pkg/authn/ui/page_templates/basic/login.template"); err != nil {
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
		{
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

func TestRenderTemplate(t *testing.T) {
	// Define the table structure for template rendering tests
	var testcases = []struct {
		name      string
		template  string
		disabled  bool
		pageTitle string
		data      map[string]interface{}
		shouldErr bool
	}{
		{
			name:     "render portal template",
			template: "basic/portal",
			data: map[string]interface{}{
				"title": "My Portal",
			},
		},
		{
			name:     "render mobile access template",
			template: "basic/apps_mobile_access",
		},
		{
			name:      "render login template",
			template:  "basic/login",
			pageTitle: translate.Translate("sign_in", translate.English, nil),
			data: map[string]interface{}{
				"authenticated": false,
				"login_options": map[string]interface{}{
					"authenticators": []interface{}{
						map[string]interface{}{
							"background_color":     "#324960",
							"class_name":           "las la-key la-2x",
							"color":                "white",
							"realm":                "local",
							"registration_enabled": "yes",
							"text":                 "LOCAL",
							"text_color":           "#37474f",
						},
					},
					"authenticators_required":   "no",
					"default_realm":             "local",
					"form_required":             "yes",
					"hide_contact_support_link": "yes",
					"hide_forgot_username_link": "yes",
					"hide_links":                "no",
					"hide_register_link":        "no",
					"identity_required":         "yes",
					"realm_dropdown_required":   "no",
					"realms": []interface{}{
						map[string]interface{}{
							"default": "yes",
							"label":   "LOCAL",
							"realm":   "local",
						},
					},
				},
				"i18n_provide_username_or_email": translate.Translate("provide_username_or_email", translate.English, nil),
				"i18n_back_action":               translate.Translate("back_action", translate.English, nil),
				"i18n_proceed_action":            translate.Translate("proceed_action", translate.English, nil),
				"i18n_register_action":           translate.Translate("register_action", translate.English, nil),
				"i18n_forgot_username_question":  translate.Translate("forgot_username_question", translate.English, nil),
				"i18n_contact_support_action":    translate.Translate("contact_support_action", translate.English, nil),
			},
		},
		{
			name:     "render generic template",
			template: "basic/generic",
			data:     map[string]interface{}{},
		},
		{
			name:     "render sandbox template",
			template: "basic/sandbox",
		},
		{
			name:     "render registration template",
			template: "basic/register",
			data:     map[string]interface{}{},
		},
		{
			name:      "render sso applications template",
			template:  "basic/apps_sso",
			pageTitle: "AWS SSO",
			data: map[string]interface{}{
				"role_count": 1,
				"roles": []interface{}{
					map[string]interface{}{
						"Name":         "foo",
						"AccountID":    "1234567890",
						"ProviderName": "aws",
					},
				},
			},
		},
		{
			name:      "render whoami template",
			template:  "basic/whoami",
			pageTitle: translate.Translate("user_identity_heading", translate.English, nil),
			data: map[string]interface{}{
				"token":             `{"authenticated": true}`,
				"i18n_portal_label": translate.Translate("portal_label", translate.English, nil),
				"i18n_sign_out":     translate.Translate("sign_out", translate.English, nil),
			},
		},
	}

	f := NewFactory()
	if err := f.AddBuiltinTemplates(); err != nil {
		t.Fatalf("failed to load builtin templates: %v", err)
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				t.Skip("Test disabled")
				return
			}

			args := f.GetArgs()

			args.PageTitle = tc.pageTitle

			for k, v := range tc.data {
				args.Data[k] = v
			}

			output, err := f.Render(tc.template, args)

			if (err != nil) != tc.shouldErr {
				t.Errorf("Render() error = %v, wantErr %v", err, tc.shouldErr)
				return
			}

			if !tc.shouldErr {
				if output == nil {
					t.Errorf("Render() returned nil buffer")
				} else if output.Len() == 0 {
					t.Errorf("Render() returned empty output for template %s", tc.template)
				}
			}
		})
	}
}
