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
	"reflect"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/state/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestStateDirectives(t *testing.T) {
	for _, lines := range [][]string{nil, {""}, {"directory"}, {"directory relative"}, {"directory /"}, {"unknown /tmp/state"}, {"directory /tmp/state", "directory /tmp/other"}, {"directory /tmp/state extra"}, {"directory /tmp/state\nother"}, {"directory /tmp/state\rother"}, {`"unterminated`}} {
		if c, err := parser.NewStateConfigFromDirectives(lines); err == nil || c != nil {
			t.Fatalf("invalid directive accepted: %#v", lines)
		}
	}
	lines := []string{cfgutil.EncodeArgs([]string{"directory", "/tmp/auth state"})}
	before := append([]string(nil), lines...)
	c, err := parser.NewStateConfigFromDirectives(lines)
	if err != nil || c.Directory != "/tmp/auth state" || !reflect.DeepEqual(lines, before) {
		t.Fatal("quoted path was not preserved")
	}
}
func ExampleNewStateConfigFromDirectives() {
	c, err := parser.NewStateConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"directory", "/var/lib/authcrunch"})})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Directory)
	// Output: /var/lib/authcrunch
}
