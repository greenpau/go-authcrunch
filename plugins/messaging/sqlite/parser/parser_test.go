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
	"github.com/greenpau/go-authcrunch/plugins/messaging/sqlite/parser"
	"testing"
)

func TestSQLiteMessagingParser(t *testing.T) {
	valid := []string{"name fixture", `path "/private/mail queue.db"`, "timeout 500ms"}
	c, err := parser.NewSQLiteMessagingConfigFromDirectives(valid)
	if err != nil || c.Path != "/private/mail queue.db" || c.Timeout != "500ms" {
		t.Fatal(c, err)
	}
	for _, bad := range [][]string{nil, {"name x"}, {"name x", "path relative"}, {"name x", "path /x", "timeout 0s"}, {"name x", "path /x", "name y"}, {"name x", "path /x", "other y"}, {"name x y"}, {"name \""}, {"name x\npath /x"}, {"name x\x00"}, {"name \xff"}, {"name \"\""}} {
		c, err := parser.NewSQLiteMessagingConfigFromDirectives(bad)
		if c != nil || err == nil {
			t.Fatal("accepted invalid directives", c)
		}
	}
	c, err = parser.NewSQLiteMessagingConfigFromDirectives([]string{"name fixture", "path /private/mail.db"})
	if err != nil || c.Timeout != "1s" {
		t.Fatal(c, err)
	}
}

func ExampleNewSQLiteMessagingConfigFromDirectives() {
	config, err := parser.NewSQLiteMessagingConfigFromDirectives([]string{"name notifications", "path /private/auth/outbox.db"})
	if err != nil {
		panic(err)
	}
	fmt.Println(config.Name, config.Timeout)
	// Output: notifications 1s
}
