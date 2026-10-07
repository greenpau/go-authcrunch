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
	"slices"
	"testing"

	"github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
)

func TestSQLiteTicketParser(t *testing.T) {
	valid := []string{"name tickets", "realm application", `path "/private/sign-in tickets.db"`, "public_origin https://portal.example.test", "issuer_url https://issuer.example.test/login"}
	original := slices.Clone(valid)
	c, err := parser.NewSQLiteTicketProviderConfigFromDirectives(valid)
	if err != nil || c.BasePath != "/auth" || c.Timeout != "1s" || c.CookieName != "AUTHP_PROVIDER_SESSION_ID" || !slices.Equal(valid, original) {
		t.Fatal(c, err)
	}
	for _, extra := range []string{"name duplicate", "cookie_name bad;name", "cookie_name __Host-TICKET", "unknown value", "base_path /api/auth", "base_path /favicon-team", "base_path //auth", "base_path /../auth", "base_path /auth/", "timeout 0s", "timeout 31s", "timeout x y", "timeout \"\"", "timeout \"", "timeout 1s\n", "timeout \x00", "timeout \xff"} {
		if got, err := parser.NewSQLiteTicketProviderConfigFromDirectives(append(slices.Clone(valid), extra)); got != nil || err == nil {
			t.Fatal("bad directive accepted", extra)
		}
	}
	for i := range valid {
		if got, err := parser.NewSQLiteTicketProviderConfigFromDirectives(append(slices.Clone(valid[:i]), valid[i+1:]...)); got != nil || err == nil {
			t.Fatal("missing required setting", i)
		}
	}
	for _, bad := range []string{"public_origin http://portal.example.test", "public_origin https://portal.example.test:", "public_origin https://portal.example.test:0", "public_origin https://[::1]:65536", "issuer_url https://issuer.example.test:99999/login", "issuer_url https://issuer.example.test:/login", "public_origin https://portal.example.test/", "public_origin https://user@portal.example.test", "public_origin https://portal.example.test#", "issuer_url https://issuer.example.test/login?", "issuer_url https://issuer.example.test/login?callback=evil", "issuer_url https://issuer.example.test/../login", "issuer_url https://issuer.example.test", "issuer_url https://portal.example.test/auth/provider/application"} {
		candidate := slices.Clone(valid)
		index := 3
		if len(bad) > 10 && bad[:10] == "issuer_url" {
			index = 4
		}
		candidate[index] = bad
		if got, err := parser.NewSQLiteTicketProviderConfigFromDirectives(candidate); got != nil || err == nil {
			t.Fatal("unsafe URL accepted", bad)
		}
	}
	c, err = parser.NewSQLiteTicketProviderConfigFromDirectives(append(slices.Clone(valid), "base_path /tenant/auth", "timeout 500ms", "cookie_name __Secure-TICKET"))
	if err != nil || c.BasePath != "/tenant/auth" || c.Timeout != "500ms" || c.CookieName != "__Secure-TICKET" {
		t.Fatal(c, err)
	}
}
func ExampleNewSQLiteTicketProviderConfigFromDirectives() {
	c, err := parser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm app", "path /private/tickets.db", "public_origin https://portal.example.test", "issuer_url https://issuer.example.test/login"})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Realm, c.BasePath, c.Timeout)
	// Output: app /auth 1s
}
