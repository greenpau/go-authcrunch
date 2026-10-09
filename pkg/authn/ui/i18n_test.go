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
	"regexp"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/translate"
	"golang.org/x/net/html"
)

func TestI18NArgs(t *testing.T) {
	for _, tc := range []struct{ language, code, direction, label string }{
		{"", "en", "ltr", "Continue"}, {"French", "fr", "ltr", "Continuer"},
		{"ar", "ar", "rtl", "متابعة"}, {"he", "he", "rtl", "המשך"},
		{"unsupported", "en", "ltr", "Continue"},
	} {
		t.Run(tc.language, func(t *testing.T) {
			f := NewFactory()
			f.Language = translate.LangID(tc.language)
			args := f.GetArgs()
			if args.LanguageCode() != tc.code || args.Direction() != tc.direction || args.Translate("continue_action") != tc.label {
				t.Fatal("incorrect language selection")
			}
			f.Language = translate.Japanese
			if args.LanguageCode() != tc.code {
				t.Fatal("arguments must snapshot the factory language")
			}
			var messages map[string]string
			if err := json.Unmarshal([]byte(args.Messages("continue_action")), &messages); err != nil {
				t.Fatal(err)
			}
			if messages["continue_action"] != tc.label {
				t.Fatal("client message differs from server translation")
			}
		})
	}
	args := &Args{Language: translate.French}
	if got := args.Translate("mfa_lifetime", 30); got != "Durée de validité : 30 secondes" {
		t.Fatalf("parameterized message: %q", got)
	}
	tmpl, err := loadTemplateFromString("escape", `<p>{{ .Translate "mfa_lifetime" .Message }}</p><script data-i18n="{{ .Messages "mfa_browser_failed" }}"></script>`)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFactory()
	f.Templates["escape"] = &Template{Template: tmpl}
	args.Message = `</p><img id="injected" src=x onerror=alert(1)>`
	body, err := f.Render("escape", args)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := html.Parse(strings.NewReader(body.String()))
	if err != nil {
		t.Fatal(err)
	}
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		if n.Data == "img" {
			t.Fatal("translated interpolation injected HTML")
		}
		if n.Data == "p" && !strings.Contains(crossDeviceNodeText(n), args.Message) {
			t.Fatal("interpolation text was not preserved")
		}
		if n.Data == "script" {
			var messages map[string]string
			if err := json.Unmarshal([]byte(crossDeviceAttr(n, "data-i18n")), &messages); err != nil {
				t.Fatal(err)
			}
			if messages["mfa_browser_failed"] != args.Translate("mfa_browser_failed") {
				t.Fatal("HTML attribute changed the client message")
			}
		}
	}
}

// This inventory is deliberately independent of handler-populated messages:
// every built-in branch must render in all supported languages and mounts.
func TestI18NTemplates(t *testing.T) {
	cases := map[string][]string{
		"login": {"single", "multiple", "external"}, "portal": {"portal"}, "generic": {"generic"}, "whoami": {"whoami"},
		"apps_sso": {"roles", "empty"}, "apps_mobile_access": {"mobile"},
		"session": {"continue", "logout"}, "cross_device": {"request", "activate", "confirm", "approve", "deny"},
		"oidc": {"consent", "form_post", "error"}, "register": {"register", "registered", "ack", "ackfail", "acked"},
		"sandbox": {"mfa_mixed_auth", "mfa_mixed_register", "password_auth", "password_recovery", "mfa_app_auth", "mfa_app_register", "mfa_u2f_auth", "mfa_u2f_register", "terminate", "error", "unknown"},
	}
	for _, lang := range []translate.LangID{translate.English, translate.German, translate.French, translate.Japanese, translate.Chinese, translate.Hebrew, translate.Arabic, translate.Russian} {
		for _, mount := range []string{"", "/tenant/auth"} {
			f := NewFactory()
			f.Language = lang
			if err := f.AddBuiltinTemplates(); err != nil {
				t.Fatal(err)
			}
			for alias, views := range cases {
				for _, view := range views {
					t.Run(string(lang)+mount+"/"+alias+"/"+view, func(t *testing.T) {
						args := f.GetArgs()
						args.BaseURL(mount)
						args.PageTitle = args.Translate("sign_in")
						args.Data["view"] = view
						args.Data["session_action"] = view
						args.Data["login_options"] = map[string]any{"default_realm": "local", "form_required": "yes", "authenticators": []any{}, "realms": []any{}}
						args.Data["cross_device_enabled"] = true
						if alias == "login" {
							options := args.Data["login_options"].(map[string]any)
							options["authenticators"] = []map[string]string{{"realm": "local", "text": "Local"}}
							if view != "single" {
								options["authenticators_required"] = "yes"
								options["authenticators"] = []map[string]string{{"realm": "local", "text": "Local"}, {"endpoint": "/oauth2/example", "text": "Example"}}
							}
							if view == "external" {
								options["form_required"] = "no"
							}
						}
						args.Data["role_count"] = 0
						if alias == "apps_sso" && view == "roles" {
							args.Data["role_count"] = 1
							args.Data["roles"] = []map[string]string{{"ProviderName": "aws", "AccountID": "123456789012", "Name": "reader"}}
						}
						args.Data["require_registration_code"] = true
						args.Data["require_accept_terms"] = true
						args.Data["id"] = "fixture"
						args.Data["registration_realm_name"] = "local"
						args.Data["registration_id"] = "registration-fixture"
						args.Data["code_uri_encoded"] = "fixture-qr"
						args.Data["display"] = "CONE-IGXV"
						args.Data["account"] = "alice@example.test"
						args.Data["csrf"] = "fixture-csrf"
						args.Data["oidc"] = oidc.Page{Kind: view, Language: lang, Title: args.Translate("oidc_consent_title"), Message: args.Translate("oidc_invalid_request"), ClientName: "Example", Username: "alice@example.test", Permissions: []oidc.PagePermission{{Title: args.Translate("oidc_account_identifier"), Description: args.Translate("oidc_account_description")}}}
						asset, _ := PageTemplates.GetAsset("basic/" + alias)
						for _, match := range regexp.MustCompile(`\.Data\.i18n_([a-z_]+)`).FindAllStringSubmatch(asset.Content, -1) {
							args.Data["i18n_"+match[1]] = translate.Translate(match[1], lang, map[string]any{"minutes": 5})
						}
						body, err := f.Render("basic/"+alias, args)
						if err != nil {
							t.Fatal(err)
						}
						doc, err := html.Parse(strings.NewReader(body.String()))
						if err != nil {
							t.Fatal(err)
						}
						for n := range doc.Descendants() {
							if n.Type != html.ElementNode {
								continue
							}
							if n.Data == "html" && (crossDeviceAttr(n, "lang") != string(lang) || crossDeviceAttr(n, "dir") != args.Direction()) {
								t.Fatal("incorrect page language/direction")
							}
							if strings.HasPrefix(crossDeviceAttr(n, "src"), "/assets/") && mount != "" {
								t.Fatal("unmounted asset")
							}
							if payload := crossDeviceAttr(n, "data-i18n"); payload != "" {
								var messages map[string]string
								if err := json.Unmarshal([]byte(payload), &messages); err != nil {
									t.Fatal(err)
								}
								for id, msg := range messages {
									if msg == id || strings.Contains(msg, "<no value>") {
										t.Fatalf("unresolved client message %s", id)
									}
								}
							}
							switch crossDeviceAttr(n, "id") {
							case "cross-device-code", "passcode", "registration_code":
								if crossDeviceAttr(n, "dir") != "ltr" {
									t.Fatal("verification codes must retain LTR order")
								}
							}
						}
						checks := map[string]string{"sandbox/password_auth": "provide_password", "sandbox/mfa_app_auth": "verify_action", "cross_device/confirm": "approve_action", "cross_device/activate": "continue_action", "oidc/consent": "oidc_allow_access", "session/logout": "sign_out"}
						if id := checks[alias+"/"+view]; id != "" && !strings.Contains(crossDeviceNodeText(doc), args.Translate(id)) {
							t.Fatalf("missing translated action %s", id)
						}
					})
				}
			}
		}
	}
}

func TestI18NTemplateCoverage(t *testing.T) {
	// Strip Go actions and inspect only actual HTML copy, including accessible names.
	// CSS, JavaScript, IDs, form values and operator-supplied data are not prose.
	actions := regexp.MustCompile(`(?s){{.*?}}`)
	letters := regexp.MustCompile(`[A-Za-z]`)
	calls := regexp.MustCompile(`\.(?:Translate|Messages)\s+((?:"[a-z_]+"\s*)+)`)
	ids := regexp.MustCompile(`"([a-z_]+)"`)
	for _, name := range PageTemplates.GetAssetPaths() {
		t.Run(name, func(t *testing.T) {
			asset, _ := PageTemplates.GetAsset(name)
			for _, call := range calls.FindAllStringSubmatch(asset.Content, -1) {
				for _, id := range ids.FindAllStringSubmatch(call[1], -1) {
					if translate.Translate(id[1], translate.English, map[string]any{"Value": 30}) == id[1] {
						t.Errorf("missing catalog message %s", id[1])
					}
				}
			}
			doc, err := html.ParseWithOptions(strings.NewReader(actions.ReplaceAllString(asset.Content, "")), html.ParseOptionEnableScripting(false))
			if err != nil {
				t.Fatal(err)
			}
			for n := range doc.Descendants() {
				if n.Type == html.TextNode && n.Parent.Data != "script" && n.Parent.Data != "style" && letters.MatchString(n.Data) {
					t.Errorf("untranslated template copy: %q", strings.TrimSpace(n.Data))
				}
				for _, a := range n.Attr {
					if (a.Key == "alt" || a.Key == "title" || a.Key == "aria-label" || a.Key == "placeholder") && letters.MatchString(a.Val) {
						t.Errorf("untranslated %s: %q", a.Key, a.Val)
					}
				}
			}
		})
	}
}
