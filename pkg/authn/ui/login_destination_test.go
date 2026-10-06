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
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var (
	loginDestinationForm     = regexp.MustCompile(`<form[^>]*action="([^"]*)" method="POST"`)
	loginDestinationProvider = regexp.MustCompile(`<a href="(oauth2/upstream[^"]*)"`)
	loginDestinationHTTP     = regexp.MustCompile(`<a href="(provider/application[^"]*)"`)
	loginDestinationScript   = regexp.MustCompile(`<script src="[^"]*/assets/js/login\.js"([^>]*)>`)
	loginDestinationData     = regexp.MustCompile(`data-([a-z-]+)="([^"]*)"`)
)

// The login page carries its own destination wherever the login can continue:
// the form target, the provider links, and the script that watches for a login
// completed in another tab. Each must hold the destination as one encoded
// value, whatever characters it contains.
func TestBasicLoginCarriesFlowDestination(t *testing.T) {
	// The portal hands over destinations as url.URL.String renders them.
	destination := "https://app.example.test/tab/a%2Fb?q=%3Cx%3E&x=one%26two&y=three+four#frag"
	for _, tc := range []struct {
		name        string
		destination string
		watch       bool
		wantQuery   bool
		wantData    map[string]string
	}{
		{
			name:        "destination",
			destination: destination,
			watch:       true,
			wantQuery:   true,
			wantData:    map[string]string{"whoami": "{mount}/whoami?probe=login", "return-url": destination},
		},
		{
			name:     "no destination",
			watch:    true,
			wantData: map[string]string{"whoami": "{mount}/whoami?probe=login", "return-url": "{mount}/portal"},
		},
		{
			// Characters a URL may not hold literally reach the script encoded,
			// and the form and provider links still carry them as one value.
			name:        "raw characters",
			destination: `https://app.example.test/tab/"<x>'`,
			watch:       true,
			wantQuery:   true,
			wantData:    map[string]string{"whoami": "{mount}/whoami?probe=login", "return-url": "https://app.example.test/tab/%22%3cx%3e%27"},
		},
		{
			name:        "fresh login",
			destination: destination,
			wantQuery:   true,
			wantData:    map[string]string{},
		},
		{
			// The portal renders only trusted destinations; the template must
			// still refuse to hand a script URL to the page script.
			name:        "script destination",
			destination: "javascript:alert(1)",
			watch:       true,
			wantQuery:   true,
			wantData:    map[string]string{"whoami": "{mount}/whoami?probe=login", "return-url": "#ZgotmplZ"},
		},
	} {
		for _, mount := range []string{"", "/tenant/auth"} {
			t.Run(tc.name+mount, func(t *testing.T) {
				f := NewFactory()
				if err := f.AddBuiltinTemplate("basic/login"); err != nil {
					t.Fatal(err)
				}
				args := f.GetArgs()
				args.BaseURL(mount)
				args.Data["login_options"] = map[string]any{
					"form_required":           "yes",
					"authenticators_required": "yes",
					"default_realm":           "local",
					"realms":                  []map[string]string{{"realm": "local", "default": "yes"}},
					"authenticators": []map[string]string{
						{"realm": "local", "text": "Local"},
						{"realm": "upstream", "text": "Upstream", "endpoint": "oauth2/upstream", "login_return_url_enabled": "yes"},
						{"realm": "application", "text": "Application", "endpoint": "provider/application"},
					},
				}
				if tc.destination != "" {
					args.Data["login_return_url"] = tc.destination
				}
				args.Data["login_elsewhere_enabled"] = tc.watch
				body, err := f.Render("basic/login", args)
				if err != nil {
					t.Fatal(err)
				}
				page := body.String()

				form := loginDestinationForm.FindStringSubmatch(page)
				provider := loginDestinationProvider.FindStringSubmatch(page)
				httpLogin := loginDestinationHTTP.FindStringSubmatch(page)
				if form == nil || provider == nil || httpLogin == nil {
					t.Fatal("login page lost its form or provider links")
				}
				// An HTTP login provider accepts no query on its first request.
				if httpLogin[1] != "provider/application" {
					t.Errorf("HTTP login provider link carries %q", httpLogin[1])
				}
				for target, want := range map[string]string{form[1]: mount + "/login", provider[1]: "oauth2/upstream"} {
					got, err := url.Parse(html.UnescapeString(target))
					if err != nil {
						t.Fatalf("login target %q does not parse: %v", target, err)
					}
					if got.Path != want {
						t.Errorf("login target %q has path %q, want %q", target, got.Path, want)
					}
					wantQuery := url.Values{}
					if tc.wantQuery {
						wantQuery.Set("redirect_url", tc.destination)
					}
					if got.Fragment != "" || got.Query().Encode() != wantQuery.Encode() {
						t.Errorf("login target %q carries %q#%q, want %q", target, got.RawQuery, got.Fragment, wantQuery.Encode())
					}
				}

				script := loginDestinationScript.FindStringSubmatch(page)
				if script == nil {
					t.Fatal("login page lost its script")
				}
				data := map[string]string{}
				for _, attr := range loginDestinationData.FindAllStringSubmatch(script[1], -1) {
					data[attr[1]] = html.UnescapeString(attr[2])
				}
				if len(data) != len(tc.wantData) {
					t.Errorf("login script data = %q, want %q", data, tc.wantData)
				}
				for name, want := range tc.wantData {
					if want = strings.ReplaceAll(want, "{mount}", mount); data[name] != want {
						t.Errorf("login script data-%s = %q, want %q", name, data[name], want)
					}
				}
				if strings.Contains(page, "<x>") || strings.Contains(page, "javascript:") {
					t.Error("login page rendered the destination unescaped")
				}
			})
		}
	}
}

// Submitting a fresh login, and starting over after a failed one, return to a
// login page that keeps the tab's destination and its fresh state.
func TestBasicLoginContinuationKeepsFreshDestination(t *testing.T) {
	destination := "https://app.example.test/tab?x=one%26two"
	startOver := regexp.MustCompile(`<a href="([^"]*login[^"]*)">\s*<button type="button" class="app-btn-pri">`)
	for _, tc := range []struct {
		name        string
		destination string
		fresh       bool
	}{
		{name: "fresh destination", destination: destination, fresh: true},
		{name: "fresh", fresh: true},
		{name: "destination", destination: destination},
		{name: "plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFactory()
			if err := f.AddBuiltinTemplates(); err != nil {
				t.Fatal(err)
			}
			want := url.Values{}
			if tc.fresh {
				want.Set("fresh", "1")
			}
			if tc.destination != "" {
				want.Set("redirect_url", tc.destination)
			}
			for alias, pattern := range map[string]*regexp.Regexp{"basic/login": loginDestinationForm, "basic/sandbox": startOver} {
				args := f.GetArgs()
				args.BaseURL("/auth")
				args.Data["view"] = "terminate"
				args.Data["error"] = "Too many failed attempts"
				args.Data["login_options"] = map[string]any{"form_required": "yes", "default_realm": "local", "realms": []map[string]string{{"realm": "local", "default": "yes"}}, "authenticators": []map[string]string{{"realm": "local", "text": "Local"}}}
				if tc.destination != "" {
					args.Data["login_return_url"] = tc.destination
				}
				args.Data["login_fresh"] = tc.fresh
				body, err := f.Render(alias, args)
				if err != nil {
					t.Fatal(err)
				}
				m := pattern.FindStringSubmatch(body.String())
				if m == nil {
					t.Fatalf("%s lost its login continuation", alias)
				}
				got, err := url.Parse(html.UnescapeString(m[1]))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(got.Path, "/login") || got.Query().Encode() != want.Encode() {
					t.Errorf("%s continues at %q, want /login with %q", alias, m[1], want.Encode())
				}
			}
		})
	}
}
