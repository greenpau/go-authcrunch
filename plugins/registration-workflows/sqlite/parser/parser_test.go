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
	"github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite/parser"
	"slices"
	"testing"
)

func TestSQLiteRegistrationParser(t *testing.T) {
	valid := []string{"name registration", `path "/private/registration state.db"`, "identity_store accounts", "realm staff", "email_provider mail", "public_origin https://portal.example.test"}
	original := slices.Clone(valid)
	c, err := parser.NewSQLiteRegistrationConfigFromDirectives(valid)
	if err != nil || c.Timeout != "1s" || c.BasePath != "/auth" || !slices.Equal(original, valid) {
		t.Fatal(c, err)
	}
	for _, extra := range []string{"name duplicate", "unknown value", "timeout 31s", "timeout 0", "base_path //bad", "base_path /../bad", "base_path /auth/", "base_path https://evil", "timeout x y", "timeout \"\"", "timeout \"", "timeout 1s\n", "timeout \x00", "timeout \xff"} {
		bad := append(slices.Clone(valid), extra)
		got, err := parser.NewSQLiteRegistrationConfigFromDirectives(bad)
		if got != nil || err == nil {
			t.Fatal("invalid directive accepted", extra)
		}
	}
	for _, origin := range []string{"http://portal.example.test", "https://user@portal.example.test", "https://portal.example.test/", "https://portal.example.test?x=1", "https://portal.example.test#fragment", "//portal.example.test", "https://", "https://portal.example.test:bad"} {
		bad := slices.Clone(valid)
		bad[len(bad)-1] = "public_origin " + origin
		if got, err := parser.NewSQLiteRegistrationConfigFromDirectives(bad); got != nil || err == nil {
			t.Fatal("invalid origin accepted", origin)
		}
	}
	for i := range valid {
		bad := append(slices.Clone(valid[:i]), valid[i+1:]...)
		if got, err := parser.NewSQLiteRegistrationConfigFromDirectives(bad); got != nil || err == nil {
			t.Fatal("missing required setting", i)
		}
	}
	c, err = parser.NewSQLiteRegistrationConfigFromDirectives(append(slices.Clone(valid), "base_path /", "timeout 750ms"))
	if err != nil || c.BasePath != "/" || c.Timeout != "750ms" {
		t.Fatal(c, err)
	}
}
func ExampleNewSQLiteRegistrationConfigFromDirectives() {
	c, err := parser.NewSQLiteRegistrationConfigFromDirectives([]string{"name registration", "path /private/registration.db", "identity_store accounts", "realm staff", "email_provider mail", "public_origin https://portal.example.test"})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Realm, c.BasePath, c.Timeout)
	// Output: staff /auth 1s
}
