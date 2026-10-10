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
	"io"
	"net/url"
	"path"
	"strings"

	"golang.org/x/net/html"
)

// LoginNavigation is runtime rendering context, supplied by the portal after
// destination validation. It is not template configuration or login evidence.
// ProviderPaths contains only configured OAuth/SAML initiation endpoints.
type LoginNavigation struct {
	ReturnURL     string   `json:"-" xml:"-" yaml:"-"`
	PagePath      string   `json:"-" xml:"-" yaml:"-"`
	ProviderPaths []string `json:"-" xml:"-" yaml:"-"`
	Fresh         bool     `json:"-" xml:"-" yaml:"-"`
	Watch         bool     `json:"-" xml:"-" yaml:"-"`
	Continue      bool     `json:"-" xml:"-" yaml:"-"`
}

// carryLoginNavigation upgrades ordinary HTML navigation in filesystem themes,
// including forms that work without JavaScript. Only portal-owned routes are
// modified. Script text, foreign URLs and provider callback parameters stay raw.
func carryLoginNavigation(input *bytes.Buffer, args *Args) (*bytes.Buffer, error) {
	nav := args.LoginNavigation
	base := strings.TrimSuffix(args.ActionEndpoint, "/")
	document, err := loginNavigationDocument(input.Bytes())
	if err != nil {
		return nil, err
	}
	page := loginNavigationPage(document.root, nav.PagePath)
	destination := nav.ReturnURL
	// Defense in depth for callers of the public UI factory. The portal performs
	// the stronger configured trust check before supplying this rendering context.
	if u, err := url.Parse(destination); err != nil || (destination != "" && (u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"))) {
		destination = ""
	}
	local := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil || u.IsAbs() || u.Host != "" || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "//") {
			return nil
		}
		resolved := page.ResolveReference(u)
		// A base element can make even root-relative links foreign. The UI
		// context supplies no origin with which to trust an absolute base URL.
		if resolved.IsAbs() || resolved.Host != "" {
			return nil
		}
		if resolved.Path != base && !strings.HasPrefix(resolved.Path, base+"/") {
			return nil
		}
		return resolved
	}
	eligible := func(u *url.URL) bool {
		route := strings.TrimPrefix(u.Path, base)
		if route == "" || route == "/" || route == "/portal" || route == "/login" || route == "/cross-device" {
			return true
		}
		if realm, ok := strings.CutPrefix(route, "/register/"); ok && realm != "" && !strings.Contains(realm, "/") {
			return true
		}
		for _, provider := range nav.ProviderPaths {
			if u.Path == path.Join("/", base, provider) {
				return true
			}
		}
		return false
	}
	forms := loginNavigationForms(document, nav, base, local, eligible)
	out := bytes.NewBuffer(nil)
	hidden := func(name, value string) {
		field := html.Token{Type: html.SelfClosingTagToken, Data: "input", Attr: []html.Attribute{
			{Key: "type", Val: "hidden"}, {Key: "name", Val: name}, {Key: "value", Val: value},
		}}
		out.WriteString(field.String())
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(input.Bytes()))
	for index := 0; ; index++ {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if err := tokenizer.Err(); err != io.EOF {
				return nil, err
			}
			return out, nil
		}
		raw := append([]byte(nil), tokenizer.Raw()...)
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			out.Write(raw)
			continue
		}
		token := tokenizer.Token()
		form := forms[document.elements[index]]
		changed := false
		if form.field && form.controls && !form.blocked {
			// Existing controls may precede their form through form="id". Their
			// stale reserved names (including dirname entries) must not outrank
			// the bound hidden fields. Keep the controls usable and preserve
			// ordinary names, values and other submission behavior.
			for _, key := range []string{"name", "dirname"} {
				name := navigationAttribute(&token, key)
				if name == "redirect_url" || (name == "fresh" && form.fresh) {
					removeNavigationAttribute(&token, key)
					changed = true
				}
			}
		}
		for i := range token.Attr {
			attr := &token.Attr[i]
			if attr.Val == "" && ((token.Data == "form" && attr.Key == "action") || ((token.Data == "button" || token.Data == "input") && attr.Key == "formaction")) {
				// Empty actions use the document URL. Adding only a query would
				// instead resolve against <base>, changing the submission target.
				continue
			}
			if token.Data == "a" && attr.Key == "href" && strings.HasPrefix(attr.Val, "#") {
				continue // An in-page anchor does not start another login flow.
			}
			if (token.Data == "a" && attr.Key == "href") || (token.Data == "form" && attr.Key == "action") || ((token.Data == "button" || token.Data == "input") && attr.Key == "formaction") {
				if target := local(attr.Val); target != nil && eligible(target) {
					// Keep the original relative URL and its non-navigation parameters.
					original, _ := url.Parse(attr.Val)
					query := original.Query()
					query.Set("redirect_url", destination)
					if target.Path == base+"/login" && nav.Fresh {
						query.Set("fresh", "1")
					}
					original.RawQuery = query.Encode()
					attr.Val = original.String()
					changed = true
				}
			}
		}
		if token.Data == "script" {
			source := navigationAttribute(&token, "src")
			if target := local(source); source != "" && target != nil {
				switch target.Path {
				case base + "/assets/js/login.js":
					setNavigationAttribute(&token, "data-login-destination", destination)
					next := destination
					if next == "" {
						next = base + "/portal?redirect_url="
					}
					setNavigationAttribute(&token, "data-return-url", next)
					probe := ""
					if nav.Watch && !nav.Fresh {
						probe = base + "/whoami?probe=login"
					}
					setNavigationAttribute(&token, "data-whoami", probe)
					changed = true
				case base + "/assets/js/cross_device.js":
					setNavigationAttribute(&token, "data-return-url", destination)
					changed = true
				case base + "/assets/js/refresh.js":
					if nav.Continue {
						next := destination
						if next == "" {
							next = base + "/portal?redirect_url="
						}
						setNavigationAttribute(&token, "data-next", next)
						changed = true
					}
				}
			}
		}
		if changed {
			out.WriteString(token.String())
		} else {
			out.Write(raw)
		}
		if token.Data == "form" && form.controls && !form.blocked {
			hidden("redirect_url", destination)
			if form.fresh {
				hidden("fresh", "1")
			}
		}
	}
}

// loginNavigationPage follows the first active HTML base element. Template
// contents and foreign-namespace elements do not establish the document base.
func loginNavigationPage(document *html.Node, pagePath string) *url.URL {
	page := &url.URL{Path: pagePath}
	var visit func(*html.Node) bool
	visit = func(node *html.Node) bool {
		if node.Type == html.ElementNode && node.Namespace == "" {
			if node.Data == "template" {
				return false
			}
			if node.Data == "base" {
				for _, attr := range node.Attr {
					if attr.Key != "href" {
						continue
					}
					base, err := url.Parse(attr.Val)
					if err != nil || strings.Contains(attr.Val, "\\") {
						page = &url.URL{Scheme: "invalid"}
					} else {
						page = page.ResolveReference(base)
					}
					return true
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if visit(child) {
				return true
			}
		}
		return false
	}
	visit(document)
	return page
}

func navigationAttribute(token *html.Token, name string) string {
	for _, attr := range token.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func setNavigationAttribute(token *html.Token, key, value string) {
	removeNavigationAttribute(token, key)
	token.Attr = append(token.Attr, html.Attribute{Key: key, Val: value})
}

func removeNavigationAttribute(token *html.Token, key string) {
	// Remove all duplicates so an ignored value cannot become active.
	attributes := token.Attr[:0]
	for _, attr := range token.Attr {
		if attr.Key != key {
			attributes = append(attributes, attr)
		}
	}
	token.Attr = attributes
}
