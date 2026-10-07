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
	"github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite/parser"
	"testing"
)

func TestSQLiteIdentityStoreParser(t *testing.T) {
	valid := []string{"name fixture", `path "/private/secret realms.db"`, "realm keys", "timeout 500ms"}
	c, err := parser.NewSQLiteIdentityStoreConfigFromDirectives(valid)
	if err != nil || c.Path != "/private/secret realms.db" || c.Timeout != "500ms" {
		t.Fatal(c, err)
	}
	for _, bad := range [][]string{nil, {}, {"name x", "path /file"}, append(append([]string{}, valid...), "name again"), append(append([]string{}, valid...), "unknown value"), {"name fixture", "path relative", "realm keys"}, {"name fixture", "path /file", "realm keys", "timeout 0"}, {"name x\nrealm keys"}, {"name x extra"}, {"name \xff"}, {`name "`}} {
		if c, err := parser.NewSQLiteIdentityStoreConfigFromDirectives(bad); c != nil || err == nil {
			t.Fatal("accepted malformed config")
		}
	}
}
func ExampleNewSQLiteIdentityStoreConfigFromDirectives() {
	c, err := parser.NewSQLiteIdentityStoreConfigFromDirectives([]string{"name app", "path /private/identity-stores.db", "realm signing"})
	fmt.Println(c.Name, c.Realm, c.Timeout, err)
	// Output: app signing 1s <nil>
}
