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

package parser_test

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz/external/parser"
)

func directives() []string {
	return []string{"policy reports", "version v1", "issuer issuer", "realm realm"}
}
func TestExternalAuthorizationParser(t *testing.T) {
	c, err := parser.NewExternalAuthorizationConfigFromDirectives(append(directives(), "subject claim immutable", "tenant claim tenant", "attribute roles", "attribute custom", "timeout 250ms"))
	if err != nil || c.SubjectClaim != "immutable" || c.TenantClaim != "tenant" || len(c.Attributes) != 2 || c.Timeout != "250ms" {
		t.Fatal("parser lost configuration")
	}
	for _, bad := range []string{"", "unknown private-canary", "issuer duplicate", "attribute", "subject sub", "tenant other x", "timeout 0s", "realm bad\nextra", "attribute \xff", "policy \"unterminated", "policy reports extra", `timeout ""`} {
		if c, err := parser.NewExternalAuthorizationConfigFromDirectives(append(directives(), bad)); err == nil || c != nil {
			t.Fatalf("accepted invalid directive %q", bad)
		}
	}
	if c, err := parser.NewExternalAuthorizationConfigFromDirectives(append(directives(), "attribute roles", "attribute roles")); err == nil || c != nil {
		t.Fatal("duplicate attribute accepted")
	}
	if c, err := parser.NewExternalAuthorizationConfigFromDirectives(nil); err == nil || c != nil {
		t.Fatal("empty block accepted")
	}
}
func ExampleNewExternalAuthorizationConfigFromDirectives() {
	c, err := parser.NewExternalAuthorizationConfigFromDirectives([]string{"policy reports", "version v1", "issuer https://issuer.test", "realm local"})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Policy, c.SubjectClaim, c.Timeout)
	// Output: reports sub 1s
}
