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
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Feed proposed router edits through the same checker used on production files.
// Reject unsafe names without reserving ordinary child actions or resource data.
func TestPortalReservedRouteSourceGuard(t *testing.T) {
	words := portalReservedWords(t)
	for _, tc := range []struct {
		name   string
		source string
		want   string
	}{
		{"namespace child", `func route() { match("/api/new-action") }`, ""},
		{"endpoint", `func route() { match("/login") }`, ""},
		{"reserved child data", `func route() { match("/assets/login/resource") }`, ""},
		{"marker list", `func route() { match("/recover,/forgot") }`, ""},
		{"unregistered literal", `func route() { match("/unregistered-feature/action") }`, `unregistered route word "unregistered-feature"`},
		{"unregistered list member", `func route() { match("/api/,/unregistered-feature/") }`, `unregistered route word "unregistered-feature"`},
		{"package constant", `const endpoint = "/unregistered-feature/"; func route() { match(endpoint) }`, `unregistered route word "unregistered-feature"`},
		{"local constant", `func route() { const endpoint = "/unregistered-feature/"; match(endpoint) }`, `unregistered route word "unregistered-feature"`},
		{"mounted namespace", `func route() { match(rr.Upstream.BasePath + "api/new-action") }`, ""},
		{"configured mount", `func route() { match(p.config.RefreshTokens.BasePath + "/api/new-action") }`, ""},
		{"configured mount unregistered marker", `func route() { match(p.config.RefreshTokens.BasePath + "/unregistered-feature/") }`, `unregistered route word "unregistered-feature"`},
		{"parenthesized upstream", `func route() { match((rr.Upstream).BasePath + "unregistered-feature/") }`, `unregistered route word "unregistered-feature"`},
		{"unregistered mounted name", `func route() { match(rr.Upstream.BasePath + "unregistered-feature/action") }`, `unregistered route word "unregistered-feature"`},
		{"unregistered mounted endpoint", `func route() { match(rr.Upstream.BasePath + "unregistered-feature") }`, `unregistered route word "unregistered-feature"`},
		{"mounted endpoint becomes namespace", `func route() { match(rr.Upstream.BasePath + "login/action") }`, `standalone endpoint "login"`},
		{"literal endpoint becomes namespace", `func route() { match("/login/action") }`, `standalone endpoint "login"`},
		{"assembled endpoint becomes namespace", `func route() { match("/login" + "/action") }`, `standalone endpoint "login"`},
		{"assembled namespace", `func route() { match(("/api") + ("/new-action")) }`, ""},
		{"assembled mounted namespace", `func route() { match((rr.Upstream.BasePath) + ("api" + "/new-action")) }`, ""},
		{"assembled unregistered name", `func route() { match("/" + ("unregistered-" + "feature/")) }`, `unregistered route word "unregistered-feature"`},
		{"dynamic child", `func route() { match(rr.Upstream.BasePath + "api/" + action) }`, ""},
		{"dynamic unregistered namespace", `func route() { match(rr.Upstream.BasePath + "unregistered-feature/" + action) }`, `unregistered route word "unregistered-feature"`},
		{"bare mount", `func route() { match(rr.Upstream.BasePath); match("/") }`, ""},
		{"raw string", "func route() { match(`/unregistered-feature/`) }", `unregistered route word "unregistered-feature"`},
		{"non-path text", `func route() { match("https://example.test/new-action"); match(42) }`, ""},
		{"local child switch", `func route() {}; func child() { match("/new-action") }`, ""},
		{"missing owner", `func renamed() { match("/api/") }`, "route owner route moved or disappeared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, "router.go", "package router\n"+tc.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			violations := portalRouteSourceViolations(positions, file, []string{"route"}, words)
			if tc.want == "" {
				if len(violations) != 0 {
					t.Fatalf("valid ownership rejected: %v", violations)
				}
			} else if len(violations) != 1 || !strings.Contains(violations[0], tc.want) {
				t.Fatalf("got %v, want one violation containing %q", violations, tc.want)
			}
		})
	}
}
