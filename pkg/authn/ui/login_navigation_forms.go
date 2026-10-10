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
	"bytes"
	"io"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

type loginFormDocument struct {
	root          *html.Node
	elements      map[int]*html.Node
	unbound       map[*html.Node]bool
	precedingForm map[*html.Node]*html.Node
}

type loginFormNavigation struct {
	controls, fresh, blocked, field bool
}

// loginNavigationForms plans shared controls using every possible submitter.
// GET overrides need controls even on POST forms. Conversely, a single foreign
// or protocol action forbids adding shared fields that it would also receive.
// DOM analysis includes submitters outside their form, without rewriting HTML.
func loginNavigationForms(document *loginFormDocument, nav *LoginNavigation, base string, local func(string) *url.URL, eligible func(*url.URL) bool) map[*html.Node]loginFormNavigation {
	var nodes []*html.Node
	ids := make(map[string]*html.Node)
	forms := make(map[*html.Node]*loginFormNavigation)
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if node.Namespace == "" && node.Data == "template" {
				return // Inert controls have no owner in this document.
			}
			nodes = append(nodes, node)
			if id, ok := loginNodeAttribute(node, "id"); ok && ids[id] == nil {
				ids[id] = node // The first element wins, even when it is not a form.
			}
			if node.Namespace == "" && node.Data == "form" {
				plan := &loginFormNavigation{blocked: document.unbound[node]}
				forms[node] = plan
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document.root)
	add := func(plan *loginFormNavigation, action, method string) {
		if loginHTMLKeyword(method, "dialog") {
			return
		}
		target := local(action)
		if action == "" {
			// Empty/omitted form actions submit to the document, not its base.
			target = &url.URL{Path: nav.PagePath}
		}
		if target == nil || !eligible(target) {
			plan.blocked = true
			return
		}
		// Missing/invalid method values have the HTML default of GET.
		if !loginHTMLKeyword(method, "post") {
			plan.controls = true
			if target.Path == base+"/login" && (nav.Fresh || target.Query().Get("fresh") == "1") {
				plan.fresh = true
			}
		}
	}
	for form, plan := range forms {
		action, _ := loginNodeAttribute(form, "action")
		method, _ := loginNodeAttribute(form, "method")
		add(plan, action, method)
	}
	owners := make(map[*html.Node]*html.Node)
	for _, node := range nodes {
		if node.Namespace != "" || (node.Data != "button" && node.Data != "input" && node.Data != "select" && node.Data != "textarea") {
			continue
		}
		var owner *html.Node
		if id, ok := loginNodeAttribute(node, "form"); ok {
			owner = ids[id]
		} else {
			for parent := node.Parent; parent != nil; parent = parent.Parent {
				if forms[parent] != nil {
					owner = parent
					break
				}
			}
		}
		kind, _ := loginNodeAttribute(node, "type")
		submit := (node.Data == "input" && (loginHTMLKeyword(kind, "submit") || loginHTMLKeyword(kind, "image"))) ||
			(node.Data == "button" && !loginHTMLKeyword(kind, "button") && !loginHTMLKeyword(kind, "reset"))
		if forms[owner] != nil {
			owners[node] = owner
		} else if _, explicit := loginNodeAttribute(node, "form"); !explicit && submit {
			// A malformed closing tag can remove a form from the DOM ancestry
			// while its parser-only form pointer still owns later controls. The
			// last actual form in source order is the only possible such owner.
			// Include it conservatively; do not rewrite the orphan's own fields.
			owner = document.precedingForm[node]
		}
		plan := forms[owner]
		if plan == nil || !submit {
			continue
		}
		action, ok := loginNodeAttribute(node, "formaction")
		if !ok {
			action, _ = loginNodeAttribute(owner, "action")
		}
		method, ok := loginNodeAttribute(node, "formmethod")
		if !ok {
			method, _ = loginNodeAttribute(owner, "method")
		}
		add(plan, action, method)
	}
	result := make(map[*html.Node]loginFormNavigation, len(forms))
	for node, plan := range forms {
		result[node] = *plan
	}
	for node, owner := range owners {
		plan := *forms[owner]
		plan.field = true
		result[node] = plan
	}
	return result
}

func loginNodeAttribute(node *html.Node, name string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val, true
		}
	}
	return "", false
}

// loginNavigationDocument maps active forms and controls to original token positions.
// Tag text is not an identity: the parser can discard a nested form whose tag
// matches a later, real form. Reusing the later plan at the discarded tag would
// inject fields into the outer form, potentially submitting them elsewhere.
func loginNavigationDocument(input []byte) (*loginFormDocument, error) {
	const marker = "data-authcrunch-form-position"
	var annotated bytes.Buffer
	originals := make(map[int][]html.Attribute)
	var positions []int
	tokenizer := html.NewTokenizer(bytes.NewReader(input))
	for index := 0; ; index++ {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if err := tokenizer.Err(); err != io.EOF {
				return nil, err
			}
			break
		}
		raw := append([]byte(nil), tokenizer.Raw()...)
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken {
			token := tokenizer.Token()
			if loginNavigationFormElement(token.Data) {
				originals[index] = append([]html.Attribute(nil), token.Attr...)
				positions = append(positions, index)
				setNavigationAttribute(&token, marker, strconv.Itoa(index))
				annotated.WriteString(token.String())
				if token.Data == "form" {
					// Simulate the placement of an injected hidden field. Table
					// parsing can pop or reparent the form while retaining its
					// parser-only owner, which x/net/html does not expose.
					probe := html.Token{Type: html.SelfClosingTagToken, Data: "input", Attr: []html.Attribute{
						{Key: "type", Val: "hidden"}, {Key: marker, Val: "form:" + strconv.Itoa(index)},
					}}
					annotated.WriteString(probe.String())
				}
				continue
			}
		}
		annotated.Write(raw)
	}
	document, err := html.Parse(&annotated)
	if err != nil {
		return nil, err
	}
	elements := make(map[int]*html.Node)
	probes := make(map[int]*html.Node)
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Namespace == "" {
			if node.Data == "template" {
				return
			}
			if loginNavigationFormElement(node.Data) {
				value, _ := loginNodeAttribute(node, marker)
				if index, err := strconv.Atoi(value); err == nil {
					node.Attr = originals[index]
					elements[index] = node
				} else if position, ok := strings.CutPrefix(value, "form:"); ok && node.Data == "input" {
					if index, err := strconv.Atoi(position); err == nil {
						probes[index] = node
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	unbound := make(map[*html.Node]bool)
	for index, probe := range probes {
		form := elements[index]
		if form != nil && form.Data == "form" {
			var owner *html.Node
			for parent := probe.Parent; parent != nil; parent = parent.Parent {
				if parent.Namespace == "" && parent.Data == "form" {
					owner = parent
					break
				}
			}
			unbound[form] = owner != form
		}
		probe.Parent.RemoveChild(probe)
	}
	preceding := make(map[*html.Node]*html.Node)
	var form *html.Node
	for _, index := range positions {
		node := elements[index]
		if node == nil {
			continue // Discarded tags and inert/foreign nodes are not form owners.
		}
		if node.Data == "form" {
			form = node
		} else {
			preceding[node] = form
		}
	}
	return &loginFormDocument{root: document, elements: elements, unbound: unbound, precedingForm: preceding}, nil
}

func loginNavigationFormElement(name string) bool {
	switch name {
	case "form", "input", "button", "select", "textarea":
		return true
	}
	return false
}

// loginHTMLKeyword matches a lower-case ASCII keyword as HTML requires. Unicode
// folding would treat "poſt" as POST and "reſet" as reset, although browsers use
// those attributes' invalid-value defaults (GET and submit respectively).
func loginHTMLKeyword(value, keyword string) bool {
	if len(value) != len(keyword) {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != keyword[i] {
			return false
		}
	}
	return true
}
