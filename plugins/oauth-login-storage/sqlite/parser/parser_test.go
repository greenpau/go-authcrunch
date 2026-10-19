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

package parser_test

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite/parser"
)

func TestSQLiteOAuthLoginStoreDirectives(t *testing.T) {
	for _, lines := range [][]string{nil, {"path relative"}, {"path /private/login.db", "path /private/other.db"}, {"path /private/login.db", "capacity 0"}, {"path /private/login.db", "capacity 100001"}, {"path /private/login.db", "timeout 0s"}, {"path /private/login.db", "unknown secret"}, {"path /private/login.db\nignored secret"}, {"path /private/login.db extra"}} {
		c, err := parser.NewSQLiteOAuthLoginStoreConfigFromDirectives(lines)
		if err == nil || c != nil {
			t.Fatal("invalid directives accepted")
		}
	}
	c, err := parser.NewSQLiteOAuthLoginStoreConfigFromDirectives([]string{"path /private/login.db", "capacity 12", "timeout 2s"})
	if err != nil || c.Capacity != 12 || c.Timeout != "2s" {
		t.Fatal("settings not applied")
	}
}

func ExampleNewSQLiteOAuthLoginStoreConfigFromDirectives() {
	c, err := parser.NewSQLiteOAuthLoginStoreConfigFromDirectives([]string{"path /private/oauth.db"})
	fmt.Println(c.Capacity, c.Timeout, err)
	// Output: 10000 1s <nil>
}
