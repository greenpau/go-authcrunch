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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity/password/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestPasswordHashConfigDirectives(t *testing.T) {
	for _, tc := range []struct {
		statements                            []string
		algorithm                             string
		cost, memory, iterations, parallelism int
	}{
		{nil, "bcrypt", 10, 0, 0, 0}, {[]string{"cost 8"}, "bcrypt", 8, 0, 0, 0},
		{[]string{"algorithm argon2"}, "argon2", 0, 65536, 3, 4},
		{[]string{"memory 8192", "iterations 2", "parallelism 1", "algorithm argon2"}, "argon2", 0, 8192, 2, 1},
	} {
		c, err := parser.NewPasswordHashConfigFromDirectives(tc.statements)
		if err != nil {
			t.Fatal(err)
		}
		if c.Algorithm != tc.algorithm || c.Cost != tc.cost || c.Memory != tc.memory || c.Iterations != tc.iterations || c.Parallelism != tc.parallelism {
			t.Fatal("unexpected defaults or parsed settings")
		}
	}
	for _, statements := range [][]string{{""}, {"algorithm"}, {"algorithm argon2 extra"}, {"algorithm argon2", "algorithm bcrypt"}, {"algorithm argon2", "cost 10"}, {"memory 10"}, {"algorithm argon2id"}, {"cost 0"}, {"cost -1"}, {"cost 32"}, {"cost 9999999999999999999999"}, {"memory 32", "memory 64"}, {"algorithm argon2", "parallelism 0"}, {"algorithm argon2", "iterations 11"}, {"algorithm argon2", "memory 262145"}, {"cost 10\nalgorithm argon2"}, {"cost 10\r"}, {"unknown secret-marker"}, {cfgutil.EncodeArgs([]string{"algorithm", "secret-marker with spaces"})}, {"cost \""}} {
		c, err := parser.NewPasswordHashConfigFromDirectives(statements)
		if err == nil || c != nil {
			t.Fatal("invalid directives accepted")
		}
		if strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("directive error disclosed input")
		}
	}
}

func ExampleNewPasswordHashConfigFromDirectives() {
	c, err := parser.NewPasswordHashConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"algorithm", "argon2"}),
		cfgutil.EncodeArgs([]string{"memory", "65536"}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Algorithm, c.Memory, c.Iterations, c.Parallelism)
	// Output: argon2 65536 3 4
}
