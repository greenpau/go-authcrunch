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
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestCrossDeviceTemplate(t *testing.T) {
	f := NewFactory()
	f.MetaTitle = "Example <Brand>"
	f.CustomCSSPath = "theme.css"
	if err := f.AddBuiltinTemplate("basic/cross_device"); err != nil {
		t.Fatal(err)
	}
	if err := f.AddTemplate("filesystem", "page_templates/basic/cross_device.template"); err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{"", "/tenant/auth"} {
		for _, tc := range []struct {
			view, title, action string
			buttons             []string
		}{
			{"request", "Sign in on another device", "", []string{"Copy link", "Cancel"}},
			{"activate", "Sign in to continue", "/cross-device/begin", []string{"Continue"}},
			{"confirm", "Approve sign in", "/cross-device/confirm", []string{"Approve", "Deny"}},
			{"approve", "Sign-in approved", "", nil},
			{"deny", "Sign-in denied", "", nil},
		} {
			t.Run(mount+"/"+tc.view, func(t *testing.T) {
				args := f.GetArgs()
				args.BaseURL(mount)
				args.PageTitle = "Sign in on another device"
				args.Data["view"] = tc.view
				// Escaping sentinels exercise both text and attribute contexts.
				args.Data["account"] = `Alice <img src=x onerror="alert(1)"> & Co`
				args.Data["display"] = "ABCD-EFGH"
				args.Data["code"] = `activation<&"code`
				args.Data["csrf"] = `binding<&"csrf`
				body, err := f.Render("basic/cross_device", args)
				if err != nil {
					t.Fatal(err)
				}
				filesystem, err := f.Render("filesystem", args)
				if err != nil {
					t.Fatal(err)
				}
				if body.String() != filesystem.String() {
					t.Fatal("filesystem and embedded templates differ")
				}
				root, err := html.Parse(strings.NewReader(body.String()))
				if err != nil {
					t.Fatal(err)
				}
				var title, heading, account, display string
				var buttons, styles, decisions []string
				var copyStatus *html.Node
				fields := make(map[string]string)
				forms := 0
				for n := range root.Descendants() {
					if n.Type != html.ElementNode {
						continue
					}
					for _, a := range n.Attr {
						if strings.HasPrefix(a.Key, "on") {
							t.Fatal("untrusted text became an event handler")
						}
					}
					if crossDeviceAttr(n, "id") == "cross-device-copy-status" {
						copyStatus = n
					}
					switch n.Data {
					case "title":
						title = crossDeviceNodeText(n)
					case "h1":
						heading = crossDeviceNodeText(n)
					case "strong":
						if crossDeviceAttr(n, "id") == "cross-device-code" {
							display = crossDeviceNodeText(n)
						} else {
							account = crossDeviceNodeText(n)
						}
					case "form":
						forms++
						if crossDeviceAttr(n, "method") != "post" || crossDeviceAttr(n, "action") != mount+tc.action {
							t.Fatal("incorrect mounted POST form")
						}
					case "input":
						if crossDeviceAttr(n, "type") != "hidden" {
							t.Fatal("approval credentials must stay hidden")
						}
						fields[crossDeviceAttr(n, "name")] = crossDeviceAttr(n, "value")
					case "button":
						buttons = append(buttons, crossDeviceNodeText(n))
						if crossDeviceAttr(n, "name") == "decision" {
							decisions = append(decisions, crossDeviceAttr(n, "value"))
						}
					case "link":
						if crossDeviceAttr(n, "rel") == "stylesheet" {
							styles = append(styles, crossDeviceAttr(n, "href"))
						}
					}
				}
				if title != f.MetaTitle+" - "+tc.title || heading != tc.title {
					t.Fatal("document and visible titles must describe the current step")
				}
				if !slices.Equal(buttons, tc.buttons) {
					t.Fatalf("unexpected actions: %v", buttons)
				}
				if tc.view == "request" {
					if copyStatus == nil || crossDeviceAttr(copyStatus, "role") != "status" || crossDeviceNodeText(copyStatus) != "" {
						t.Fatal("copy feedback needs an initially empty live status region")
					}
					for n := copyStatus; n != nil; n = n.Parent {
						for _, a := range n.Attr {
							if a.Key == "hidden" || (a.Key == "aria-hidden" && a.Val == "true") {
								t.Fatal("copy feedback must be exposed before its message changes")
							}
						}
					}
				}
				if len(styles) < 2 || styles[len(styles)-2] != mount+"/assets/css/basic.css" || styles[len(styles)-1] != mount+"/assets/css/custom.css" {
					t.Fatal("custom CSS must follow the mounted theme stylesheet")
				}
				if tc.action == "" {
					if forms != 0 || len(fields) != 0 {
						t.Fatal("non-decision view exposed an authentication form")
					}
				} else if forms != 1 || fields["csrf"] != args.Data["csrf"] || display != args.Data["display"] {
					t.Fatal("approval form lost its binding or matching code")
				}
				if tc.view == "activate" && (len(fields) != 2 || fields["code"] != args.Data["code"]) {
					t.Fatal("activation form lost its code")
				}
				if tc.view == "confirm" && (len(fields) != 1 || account != args.Data["account"] || !slices.Equal(decisions, []string{"approve", "deny"})) {
					t.Fatal("confirmation lost its escaped account or explicit decisions")
				}
			})
		}
	}
}

func crossDeviceAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func crossDeviceNodeText(n *html.Node) string {
	var text strings.Builder
	for child := range n.Descendants() {
		if child.Type == html.TextNode {
			text.WriteString(child.Data)
		}
	}
	return text.String()
}
