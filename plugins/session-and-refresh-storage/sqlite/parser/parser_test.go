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
	"path/filepath"
	"testing"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite/parser"
)

func TestSQLiteRefreshStorageParser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions with spaces.db")
	base := cfgutil.EncodeArgs([]string{"path", path})
	c, err := parser.NewSQLiteRefreshStorageConfigFromDirectives([]string{base, "max sessions 2", "max rotations 3", "timeout 250ms"})
	if err != nil || c.Path != path || c.MaxSessions != 2 || c.MaxRotations != 3 || c.Timeout != "250ms" {
		t.Fatal("parser rejected valid config", err)
	}
	for _, statements := range [][]string{
		nil, {}, {""}, {base, base}, {base, "timeout 1s", "timeout 2s"}, {base, "max sessions 2", "max sessions 3"},
		{base, "max sessions 0"}, {base, "max rotations -1"}, {base, "max sessions 100001"}, {base, "max rotations 999999999999999999999"},
		{base, "max sessions two"}, {base, "max rotations 2 extra"}, {base, "max_sessions 2"}, {base, "timeout 31s"}, {base, "unknown thing"},
		{base, "timeout 1s\nmax sessions 2"}, {base, "timeout \xff"}, {base, "timeout \x00"}, {"path relative"},
		{cfgutil.EncodeArgs([]string{"max sessions", "2"}), base}, {base, "max rotations"},
	} {
		if c, err := parser.NewSQLiteRefreshStorageConfigFromDirectives(statements); err == nil || c != nil {
			t.Fatalf("accepted invalid directives: %q", statements)
		}
	}
}

func ExampleNewSQLiteRefreshStorageConfigFromDirectives() {
	c, err := parser.NewSQLiteRefreshStorageConfigFromDirectives([]string{"path /run/authcrunch/refresh.db", "max sessions 100", "max rotations 16", "timeout 2s"})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Path, c.MaxSessions, c.MaxRotations, c.Timeout)
	// Output: /run/authcrunch/refresh.db 100 16 2s
}
