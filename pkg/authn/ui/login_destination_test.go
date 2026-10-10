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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	xhtml "golang.org/x/net/html"
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

func TestLegacyThemeNavigation(t *testing.T) {
	for _, base := range []string{"", "/tenant/auth"} {
		for _, destination := range []string{"", "https://app.test/a%2Fb?x=%3Cscript%3E&y=one%26two", "https://app.test/" + strings.Repeat("x", 8000), "javascript:alert(1)"} {
			t.Run(base+"/"+destination[:min(len(destination), 30)], func(t *testing.T) {
				source := `<form action="{{.ActionEndpoint}}/login?keep=1" method="POST"><button formaction="{{.ActionEndpoint}}/login">Go</button></form>
<a id="provider" href="oauth2/upstream">Provider</a><a id="register" href="register/staff">Register</a><a id="cross" href="cross-device">QR</a>
<a id="external" href="https://external.test/login">Other</a><a id="callback" href="oauth2/upstream/authorization-code-callback?state=owned">Callback</a><a id="http" href="provider/custom">HTTP</a>
<script src="{{.ActionEndpoint}}/assets/js/login.js"></script><script src="{{.ActionEndpoint}}/assets/js/refresh.js"></script><script src="{{.ActionEndpoint}}/assets/js/cross_device.js"></script>
<script>const unchanged = "<a href='login'>";</script>`
				file := filepath.Join(t.TempDir(), "legacy.template")
				if err := os.WriteFile(file, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				factory := NewFactory()
				if err := factory.AddTemplate("login", file); err != nil {
					t.Fatal(err)
				}
				args := factory.GetArgs()
				args.BaseURL(base)
				args.LoginNavigation = &LoginNavigation{ReturnURL: destination, PagePath: base + "/login", ProviderPaths: []string{"oauth2/upstream"}, Fresh: true, Watch: true, Continue: true}
				rendered, err := factory.Render("login", args)
				if err != nil {
					t.Fatal(err)
				}
				want := destination
				if strings.HasPrefix(want, "javascript:") {
					want = ""
				}
				page, err := xhtml.Parse(strings.NewReader(rendered.String()))
				if err != nil {
					t.Fatal(err)
				}
				var visit func(*xhtml.Node)
				visits := 0
				visit = func(node *xhtml.Node) {
					attrs := map[string]string{}
					for _, attr := range node.Attr {
						attrs[attr.Key] = attr.Val
					}
					if node.Type == xhtml.ElementNode {
						key := ""
						if node.Data == "form" {
							key = "action"
						}
						if node.Data == "button" {
							key = "formaction"
						}
						if node.Data == "a" {
							key = "href"
						}
						if key != "" {
							target, err := url.Parse(attrs[key])
							if err != nil {
								t.Fatal(err)
							}
							if attrs["id"] == "external" || attrs["id"] == "callback" || attrs["id"] == "http" {
								if target.Query().Has("redirect_url") {
									t.Fatal("rewrote provider-owned/foreign navigation")
								}
							} else {
								visits++
								if !target.Query().Has("redirect_url") || target.Query().Get("redirect_url") != want {
									t.Fatal("lost transaction destination")
								}
								if node.Data == "form" && (target.Query().Get("fresh") != "1" || target.Query().Get("keep") != "1") {
									t.Fatal("lost freshness or unrelated query")
								}
							}
						}
						if node.Data == "script" && strings.HasSuffix(attrs["src"], "/login.js") {
							if attrs["data-whoami"] != "" || attrs["data-login-destination"] != want {
								t.Fatal("fresh page watches another login or loses destination")
							}
						}
					}
					for child := node.FirstChild; child != nil; child = child.NextSibling {
						visit(child)
					}
				}
				visit(page)
				if visits != 5 || !strings.Contains(rendered.String(), `const unchanged = "<a href='login'>";`) {
					t.Fatal("changed script content or missed navigation")
				}
			})
		}
	}
}

func TestRenderingWithoutLoginNavigationPreservesOutput(t *testing.T) {
	const source = `<FORM action='/login'><button>Go</button></FORM>`
	file := filepath.Join(t.TempDir(), "ordinary.template")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	factory := NewFactory()
	if err := factory.AddTemplate("ordinary", file); err != nil {
		t.Fatal(err)
	}
	for _, args := range []*Args{nil, factory.GetArgs()} {
		rendered, err := factory.Render("ordinary", args)
		if err != nil || rendered.String() != source {
			t.Fatal("rendering without optional context changed", err)
		}
	}
}

func TestLegacyThemeGETFormsAndBase(t *testing.T) {
	const destination = "https://app.test/own?x=one%26two"
	for _, tc := range []struct {
		name, baseTag, page string
		foreign             bool
	}{
		{name: "default GET", page: "/tenant/auth/login"},
		{name: "local base", baseTag: `<base href="/tenant/auth/">`, page: "/tenant/auth/sandbox/session"},
		{name: "inert base", baseTag: `<template><base href="https://elsewhere.test/"></template>`, page: "/tenant/auth/login"},
		{name: "foreign base", baseTag: `<base href="https://elsewhere.test/tenant/auth/">`, page: "/tenant/auth/login", foreign: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := tc.baseTag + `<form action="login"><input name="redirect_url" value="stale"><button>Continue</button></form><a href="#section">Section</a><a href="login">Login</a><script src="/tenant/auth/assets/js/login.js"></script>`
			file := filepath.Join(t.TempDir(), "legacy-get.template")
			if err := os.WriteFile(file, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			factory := NewFactory()
			if err := factory.AddTemplate("login", file); err != nil {
				t.Fatal(err)
			}
			args := factory.GetArgs()
			args.BaseURL("/tenant/auth")
			args.LoginNavigation = &LoginNavigation{ReturnURL: destination, PagePath: tc.page, Fresh: true}
			output, err := factory.Render("login", args)
			if err != nil {
				t.Fatal(err)
			}
			if tc.foreign {
				if output.String() != source {
					t.Fatal("rewrote navigation/assets owned by a foreign base URL")
				}
				return
			}
			page, err := xhtml.Parse(strings.NewReader(output.String()))
			if err != nil {
				t.Fatal(err)
			}
			var destinations, freshness []string
			var visit func(*xhtml.Node)
			visit = func(node *xhtml.Node) {
				attrs := map[string]string{}
				for _, attr := range node.Attr {
					attrs[attr.Key] = attr.Val
				}
				if node.Type == xhtml.ElementNode && node.Data == "input" {
					switch attrs["name"] {
					case "redirect_url":
						destinations = append(destinations, attrs["value"])
					case "fresh":
						freshness = append(freshness, attrs["value"])
					}
				}
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(page)
			if len(destinations) != 1 || destinations[0] != destination || len(freshness) != 1 || freshness[0] != "1" {
				t.Fatal("GET submission loses its first destination or freshness control")
			}
			if !strings.Contains(output.String(), `<a href="#section">`) {
				t.Fatal("rewrote a fragment-only link")
			}
		})
	}
}

func TestLegacyThemeFormOverrides(t *testing.T) {
	const destination = "https://app.test/own?x=one%26two"
	for _, tc := range []struct {
		name, source string
		wantControls bool
		emptyAction  bool
	}{
		{name: "empty action uses document", source: `<base href="/auth/"><form action=""><button>Continue</button></form>`, wantControls: true, emptyAction: true},
		{name: "empty override uses document", source: `<base href="/auth/"><form action="login"><button formaction="">Continue</button></form>`, wantControls: true, emptyAction: true},
		{name: "ASCII mixed case POST", source: `<form action="login" method="PoSt"><button>Continue</button></form>`},
		{name: "Unicode POST lookalike defaults to GET", source: `<form action="login" method="poſt"><button>Continue</button></form>`, wantControls: true},
		{name: "Unicode POST override defaults to GET", source: `<form action="login" method="post"><button formmethod="poſt">Continue</button></form>`, wantControls: true},
		{name: "ASCII mixed case reset does not submit", source: `<form action="login"><button type="ReSeT" formaction="https://external.test/receive">Reset</button></form>`, wantControls: true},
		{name: "Unicode reset lookalike submits externally", source: `<form action="login"><button type="reſet" formaction="https://external.test/receive">Continue</button></form>`},
		{name: "POST only", source: `<form action="login" method="post"><button>Continue</button></form>`},
		{name: "GET method override", source: `<form action="login" method="post"><button formmethod="get">Continue</button></form>`, wantControls: true},
		{name: "GET external submitter", source: `<button form="login-form" formmethod="get">Continue</button><form id="login-form" action="login" method="post"></form>`, wantControls: true},
		{name: "invalid override defaults to GET", source: `<form action="login" method="post"><input type="submit" formmethod="invalid"></form>`, wantControls: true},
		{name: "dialog override does not submit", source: `<form action="login" method="post"><button formmethod="dialog" formaction="https://external.test/receive">Continue</button></form>`},
		{name: "foreign action override", source: `<form action="login"><button formaction="https://external.test/receive">Continue</button></form>`},
		{name: "foreign associated submitter", source: `<button form="login-form" formaction="https://external.test/receive">Continue</button><form id="login-form" action="login"></form>`},
		{name: "associated submitter belongs to another form", source: `<form action="login"><button form="foreign" formaction="https://external.test/receive">Continue</button></form><form id="foreign" action="https://external.test/receive"></form>`, wantControls: true},
		{name: "non-submitting button", source: `<form action="login"><button type="button" formaction="https://external.test/receive">Continue</button></form>`, wantControls: true},
		{name: "provider protocol override", source: `<form action="login"><input type="submit" formaction="provider/ticket"></form>`},
		{name: "inert foreign submitter", source: `<template><button form="login-form" formaction="https://external.test/receive">Continue</button></template><form id="login-form" action="login"></form>`, wantControls: true},
		{name: "closed ancestor preserves parser form owner", source: `<div><form action="login"></div><button formaction="https://external.test/receive">Continue</button>`},
		{name: "reparented table form associates foreign submitter", source: `<table><b><form action="login"><tr><td><button formaction="https://external.test/receive">Continue</button></td></tr></form></b></table>`},
		{name: "table parser associates foreign submitter", source: `<table><form action="login"><tr><td><button formaction="https://external.test/receive">Continue</button></td></tr></form></table>`},
		{name: "first duplicate ID owns submitter", source: `<div id="login-form"></div><button form="login-form" formaction="https://external.test/receive">Continue</button><form id="login-form" action="login"></form>`, wantControls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "override.template")
			if err := os.WriteFile(file, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			factory := NewFactory()
			if err := factory.AddTemplate("login", file); err != nil {
				t.Fatal(err)
			}
			args := factory.GetArgs()
			args.BaseURL("/auth")
			args.LoginNavigation = &LoginNavigation{ReturnURL: destination, PagePath: "/auth/login", Fresh: true}
			output, err := factory.Render("login", args)
			if err != nil {
				t.Fatal(err)
			}
			if tc.emptyAction && !strings.Contains(output.String(), `action=""`) {
				t.Error("empty action stopped submitting to the document URL")
			}
			var fields []string
			tokenizer := xhtml.NewTokenizer(strings.NewReader(output.String()))
			for kind := tokenizer.Next(); kind != xhtml.ErrorToken; kind = tokenizer.Next() {
				if kind != xhtml.StartTagToken && kind != xhtml.SelfClosingTagToken {
					continue
				}
				token := tokenizer.Token()
				if token.Data == "input" && navigationAttribute(&token, "type") == "hidden" {
					fields = append(fields, navigationAttribute(&token, "name"))
				}
			}
			if tc.wantControls {
				if strings.Join(fields, ",") != "redirect_url,fresh" {
					t.Errorf("GET submission lacks navigation controls: %v", fields)
				}
			} else if len(fields) != 0 {
				t.Errorf("shared form controls would send portal navigation to an unrelated action: %v", fields)
			}
		})
	}
}

// A form is identified by its parsed element, not its opening-tag text. The
// parser can ignore a nested form, and identical real tags can have different
// submitters. Neither case may copy a navigation plan into the wrong form.
func TestLegacyThemeFormIdentity(t *testing.T) {
	const source = `<form id="foreign" action="https://external.test/receive"><form action="login"><button>External</button></form></form>
<template><form action="login"><button>Inert</button></form></template>
<form action="login"><button>Local</button></form>
<form action="login"><button formaction="https://external.test/receive">Mixed</button></form>
<form action="login" data-authcrunch-form-position="original"><button>Marker</button></form>`
	file := filepath.Join(t.TempDir(), "identity.template")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	factory := NewFactory()
	if err := factory.AddTemplate("login", file); err != nil {
		t.Fatal(err)
	}
	args := factory.GetArgs()
	args.BaseURL("/auth")
	args.LoginNavigation = &LoginNavigation{ReturnURL: "https://app.test/own", PagePath: "/auth/login", Fresh: true}
	output, err := factory.Render("login", args)
	if err != nil {
		t.Fatal(err)
	}
	page, err := xhtml.Parse(strings.NewReader(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	var fields []int
	var visit func(*xhtml.Node)
	visit = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode && node.Data == "form" {
			count := 0
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				name, _ := loginNodeAttribute(child, "name")
				if child.Data == "input" && (name == "redirect_url" || name == "fresh") {
					count++
				}
			}
			fields = append(fields, count)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(page)
	if diff := cmp.Diff([]int{0, 0, 2, 0, 2}, fields); diff != "" {
		t.Errorf("navigation fields belong to the wrong forms (-want +got):\n%s", diff)
	}
	if strings.Count(output.String(), "data-authcrunch-form-position") != 1 || !strings.Contains(output.String(), `data-authcrunch-form-position="original"`) {
		t.Error("internal form positions leaked into the rendered page or replaced a theme attribute")
	}
}

func TestLegacyThemeScriptFirstSource(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		wantBound    bool
	}{
		{name: "core source wins", source: `<script src="/auth/assets/js/login.js" src="https://external.test/custom.js"></script>`, wantBound: true},
		{name: "foreign source wins", source: `<script src="https://external.test/custom.js" src="/auth/assets/js/login.js"></script>`},
		{name: "empty source wins", source: `<script src="" src="/auth/assets/js/login.js"></script>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "script.template")
			if err := os.WriteFile(file, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			factory := NewFactory()
			if err := factory.AddTemplate("login", file); err != nil {
				t.Fatal(err)
			}
			args := factory.GetArgs()
			args.BaseURL("/auth")
			args.LoginNavigation = &LoginNavigation{ReturnURL: "https://app.test/own", PagePath: "/auth/login", Watch: true}
			output, err := factory.Render("login", args)
			if err != nil {
				t.Fatal(err)
			}
			if bound := strings.Contains(output.String(), "data-login-destination="); bound != tc.wantBound {
				t.Fatalf("script binding = %v, want %v", bound, tc.wantBound)
			}
			if !tc.wantBound && output.String() != tc.source {
				t.Error("rewrote a script whose active source is not a core asset")
			}
		})
	}
}

func TestLegacyThemeReservedFormControls(t *testing.T) {
	const source = `<input form="local" name="redirect_url" name="ordinary" value="stale">
<textarea form="local" name="fresh">0</textarea>
<select form="local" name="redirect_url"><option>stale</option></select>
<input form="local" name="note" dirname="redirect_url" value="ordinary">
<textarea form="local" name="message" dirname="fresh">ordinary</textarea>
<form id="local" action="login"><button id="submit" name="redirect_url" value="stale">Continue</button></form>
<input form="foreign" name="redirect_url" value="foreign"><form id="foreign" action="https://external.test/receive"></form>
<input name="redirect_url" value="unowned">`
	for _, fresh := range []bool{false, true} {
		t.Run(strconv.FormatBool(fresh), func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "controls.template")
			if err := os.WriteFile(file, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			factory := NewFactory()
			if err := factory.AddTemplate("login", file); err != nil {
				t.Fatal(err)
			}
			args := factory.GetArgs()
			args.BaseURL("/auth")
			args.LoginNavigation = &LoginNavigation{ReturnURL: "https://app.test/own", PagePath: "/auth/login", Fresh: fresh}
			output, err := factory.Render("login", args)
			if err != nil {
				t.Fatal(err)
			}
			tokenizer := xhtml.NewTokenizer(strings.NewReader(output.String()))
			var originalDestinations, freshness, ordinary, submit int
			for kind := tokenizer.Next(); kind != xhtml.ErrorToken; kind = tokenizer.Next() {
				if kind != xhtml.StartTagToken && kind != xhtml.SelfClosingTagToken {
					continue
				}
				token := tokenizer.Token()
				if navigationAttribute(&token, "type") == "hidden" {
					continue
				}
				for _, attr := range token.Attr {
					if attr.Key != "name" && attr.Key != "dirname" {
						continue
					}
					switch attr.Val {
					case "redirect_url":
						originalDestinations++
					case "fresh":
						freshness++
					case "note", "message":
						ordinary++
					default:
						t.Errorf("ignored duplicate name became active: %q", attr.Val)
					}
				}
				if token.Data == "button" && navigationAttribute(&token, "id") == "submit" {
					submit++
					for _, attr := range token.Attr {
						if attr.Key == "disabled" {
							t.Error("reserved navigation name disabled the submit button")
						}
					}
				}
			}
			wantFreshness := 2
			if fresh {
				wantFreshness = 0
			}
			if originalDestinations != 2 || freshness != wantFreshness || ordinary != 2 || submit != 1 {
				t.Errorf("control contracts changed: destinations=%d freshness=%d ordinary=%d submit=%d", originalDestinations, freshness, ordinary, submit)
			}
		})
	}
}
