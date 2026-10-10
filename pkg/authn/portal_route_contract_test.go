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

package authn

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"gopkg.in/yaml.v3"
)

type reservedPortalWord struct {
	Kind  string `json:"kind"`
	Owner string `json:"owner"`
	Mount string `json:"mount"`
}

func portalReservedWords(t *testing.T) map[string]reservedPortalWord {
	t.Helper()
	data, err := os.ReadFile("testdata/reserved_route_words.json")
	if err != nil {
		t.Fatal(err)
	}
	var words map[string]reservedPortalWord
	if err := json.Unmarshal(data, &words); err != nil {
		t.Fatal(err)
	}
	if len(words) == 0 {
		t.Fatal("reserved route vocabulary is empty")
	}
	for word, entry := range words {
		if word == "" || strings.ContainsAny(word, "/ ,?#") || word != strings.ToLower(word) || entry.Owner == "" {
			t.Fatalf("invalid reserved route word or missing owner: %q", word)
		}
		switch entry.Kind {
		case "namespace", "endpoint", "early_namespace", "asset_prefix", "mount":
		default:
			t.Fatalf("reserved route word %q has unknown kind %q", word, entry.Kind)
		}
		switch entry.Mount {
		case "allow":
			if entry.Kind != "mount" {
				t.Fatalf("route owner %q cannot also be a mount", word)
			}
		case "deny_segment", "deny_prefix":
			if entry.Kind == "mount" {
				t.Fatalf("mount convention %q must remain usable as a mount", word)
			}
		default:
			t.Fatalf("reserved route word %q has unknown mount rule %q", word, entry.Mount)
		}
	}
	return words
}

// Guard the actual extraction/dispatch vocabulary, including routes omitted from
// OpenAPI. New words require a conscious ownership decision in the catalogue.
// These functions operate on full request paths; feature-local child switches
// intentionally have a different scope and do not belong in this scan.
func TestPortalReservedRouteWords(t *testing.T) {
	words := portalReservedWords(t)
	sources := map[string][]string{
		"extract_base_path.go":     {"extractBasePath", "extractBaseURLPath", "extractBasePathPrefix"},
		"serve_http.go":            {"ServeHTTP"},
		"respond_http.go":          {"handleHTTP", "authorizeRequest"},
		"respond_json.go":          {"handleJSON"},
		"respond_api.go":           {"handleAPI"},
		"cross_device_http.go":     {"crossDeviceRouteIndex"},
		"handle_provider_login.go": {"providerLoginRouteIndex"},
	}
	for filename, functions := range sources {
		t.Run(filename, func(t *testing.T) {
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, filename, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, violation := range portalRouteSourceViolations(positions, file, functions, words) {
				t.Error(violation)
			}
		})
	}
}

func portalRouteSourceViolations(positions *token.FileSet, file *ast.File, functions []string, words map[string]reservedPortalWord) []string {
	var violations []string
	found := make(map[string]bool)
	check := func(node ast.Node) bool {
		value, ok := portalRouteString(node)
		if !ok {
			return true
		}
		// GetBaseURL accepts a comma-separated sequence of markers.
		for marker := range strings.SplitSeq(value, ",") {
			if !strings.HasPrefix(marker, "/") || marker == "/" {
				continue
			}
			word, _, _ := strings.Cut(strings.TrimPrefix(marker, "/"), "/")
			entry, ok := words[word]
			if !ok {
				violations = append(violations, fmt.Sprintf("%s: unregistered route word %q in %q; consult testdata/reserved_route_words.json and coding-directives/references/portal-routing.md", positions.Position(node.Pos()), word, marker))
				continue
			}
			if entry.Kind == "endpoint" && marker != "/"+word {
				violations = append(violations, fmt.Sprintf("%s: standalone endpoint %q cannot become a namespace without ownership review", positions.Position(node.Pos()), word))
			}
		}
		// Inspect the assembled path once: a child fragment such as "/logout"
		// in "/api" + "/logout" is not a separate top-level route.
		return false
	}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && slices.Contains(functions, function.Name.Name) {
			found[function.Name.Name] = true
			ast.Inspect(function.Body, check)
		}
		// Include named path literals introduced in these source files.
		if declaration, ok := declaration.(*ast.GenDecl); ok && declaration.Tok == token.CONST {
			ast.Inspect(declaration, check)
		}
	}
	for _, name := range functions {
		if !found[name] {
			violations = append(violations, fmt.Sprintf("route owner %s moved or disappeared; update the scan's ownership boundary", name))
		}
	}
	return violations
}

// Resolve literal concatenations and the trailing-slash Upstream.BasePath used
// by full-path dispatchers. Dynamic expressions and external constants still
// need source review; this deliberately does not implement Go data-flow analysis.
func portalRouteString(node ast.Node) (string, bool) {
	switch node := node.(type) {
	case *ast.BasicLit:
		if node.Kind == token.STRING {
			value, err := strconv.Unquote(node.Value)
			return value, err == nil
		}
	case *ast.ParenExpr:
		return portalRouteString(node.X)
	case *ast.SelectorExpr:
		upstream, ok := ast.Unparen(node.X).(*ast.SelectorExpr)
		if ok && upstream.Sel.Name == "Upstream" && node.Sel.Name == "BasePath" {
			return "/", true
		}
	case *ast.BinaryExpr:
		if node.Op == token.ADD {
			left, leftOK := portalRouteString(node.X)
			right, rightOK := portalRouteString(node.Y)
			return left + right, leftOK && rightOK
		}
	}
	return "", false
}

// Authored paths supply the cases; the reserved vocabulary independently
// constrains their ownership. Newly documented endpoints join this matrix
// without maintaining a duplicate endpoint list in the test.
func TestPortalRouteContract(t *testing.T) {
	words := portalReservedWords(t)
	mounts := []string{"", "/auth", "/xauth", "/tenant/auth", "/tenant/xauth", "/tenant/security", "/tenant%20name/security"}
	for word, entry := range words {
		// These names remain legal mounts under the catalogue. A new short
		// extraction marker must not start consuming part of such a mount.
		mounts = append(mounts, "/tenant/team-"+word+"/console", "/tenant/"+strings.ToUpper(word)+"/console")
		if entry.Mount != "deny_prefix" {
			mounts = append(mounts, "/tenant/"+word+"-service/console")
		}
	}
	slices.Sort(mounts)
	data, err := os.ReadFile("../../assets/openapi/content/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Paths) == 0 {
		t.Fatal("OpenAPI route inventory is empty")
	}
	var routes []string
	for route := range document.Paths {
		routes = append(routes, route)
	}
	slices.Sort(routes)
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			if route == "/" {
				return
			} // No endpoint delimiter at a bare mount.
			word, _, _ := strings.Cut(strings.TrimPrefix(route, "/"), "/")
			entry, ok := words[word]
			if !ok {
				t.Fatalf("unregistered route word %q: choose a descriptive namespace and register its owner in testdata/reserved_route_words.json", word)
			}
			switch entry.Kind {
			case "mount", "asset_prefix":
				t.Fatalf("reserved %s %q is not an API namespace", entry.Kind, word)
			case "endpoint":
				if route != "/"+word {
					t.Fatalf("standalone endpoint %q cannot own nested route %q", word, route)
				}
			case "early_namespace":
				// Discovery/OP dispatch precedes ordinary extraction. The TLS
				// ownership test and issuer-mount E2E cover those boundaries.
				return
			}
			parts := strings.Split(route, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
					parts[i] = "route-contract"
				}
			}
			endpoint := strings.Join(parts, "/")
			for _, mount := range mounts {
				r := httptest.NewRequest(http.MethodGet, "https://example.test"+mount+endpoint, nil)
				original := *r.URL
				rr := requests.NewRequest()
				extractBasePath(t.Context(), r, rr)
				if rr.Upstream.BasePath != mount+"/" || rr.Upstream.BaseURL != "https://example.test" {
					t.Errorf("route %q at mount %q: extracted %q %q; extraction and dispatch must agree", endpoint, mount, rr.Upstream.BaseURL, rr.Upstream.BasePath)
				}
				if *r.URL != original {
					t.Fatal("base extraction changed the request URL")
				}
			}
		})
	}
}
