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
	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite/parser"
	"testing"
)

func TestSQLiteSecretsParser(t *testing.T) {
	valid := []string{"name fixture", `path "/private/secret records.db"`, "record keys", "timeout 500ms"}
	c, err := parser.NewSQLiteSecretsConfigFromDirectives(valid)
	if err != nil || c.Path != "/private/secret records.db" || c.Timeout != "500ms" {
		t.Fatal(c, err)
	}
	for _, bad := range [][]string{nil, {}, {"name x", "path /file"}, append(append([]string{}, valid...), "name again"), append(append([]string{}, valid...), "unknown value"), {"name fixture", "path relative", "record keys"}, {"name fixture", "path /file", "record keys", "timeout 0"}, {"name x\nrecord keys"}, {"name x extra"}, {"name \xff"}, {`name "`}} {
		if c, err := parser.NewSQLiteSecretsConfigFromDirectives(bad); c != nil || err == nil {
			t.Fatal("accepted malformed config")
		}
	}
}
func ExampleNewSQLiteSecretsConfigFromDirectives() {
	c, err := parser.NewSQLiteSecretsConfigFromDirectives([]string{"name app", "path /private/secrets.db", "record signing"})
	fmt.Println(c.Name, c.Record, c.Timeout, err)
	// Output: app signing 1s <nil>
}
