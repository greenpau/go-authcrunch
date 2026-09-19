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
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authchal/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestAuthenticationChallengeDirectiveBoundaries(t *testing.T) {
	for _, input := range [][]string{nil, {""}, {"u2f\npassword"}, {"u2f\rpassword"}, {"u2f if"}, {"u2f if totp"}, {"password if u2f available"}, {"password if u2f not not available"}, {"password if u2f totp not available"}, {"password if u2f and not available"}, {"u2f or"}, {"or u2f"}, {"password totp or u2f"}, {"u2f or totp password"}, {"password if u2f and u2f not available"}, {"u2f", "u2f"}, {cfgutil.EncodeArgs([]string{"password totp"})}} {
		c, err := parser.NewAuthenticationChallengeConfigFromDirectives(input)
		if err == nil || c != nil {
			t.Fatalf("invalid directives accepted: %q", input)
		}
	}
	input := []string{"u2f", "password totp if u2f not available", "password if u2f and totp not available"}
	original := slices.Clone(input)
	first, err := parser.NewAuthenticationChallengeConfigFromDirectives(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parser.NewAuthenticationChallengeConfigFromDirectives(input)
	if err != nil {
		t.Fatal(err)
	}
	first.Rules[0].Challenges[0] = "changed"
	if second.Rules[0].Challenges[0] != "u2f" || !slices.Equal(input, original) {
		t.Fatal("parser results share input state")
	}
	const marker = "private-marker"
	_, err = parser.NewAuthenticationChallengeConfigFromDirectives([]string{"password if " + marker + " not available"})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatal("parser disclosed raw input")
	}
}

func FuzzAuthenticationChallengeDirectives(f *testing.F) {
	for _, statement := range []string{"password", "u2f or totp", "password totp if u2f not available", "password if u2f and totp not available", "u2f\npassword", `"password totp"`, "mfa"} {
		f.Add(statement, uint8(0))
	}
	f.Fuzz(func(t *testing.T, statement string, inventory uint8) {
		if len(statement) > 4096 {
			t.Skip()
		}
		policy, err := parser.NewAuthenticationChallengeConfigFromDirectives([]string{statement})
		if err != nil {
			if policy != nil {
				t.Fatal("invalid input returned a partial policy")
			}
			return
		}
		restored, err := parser.NewAuthenticationChallengeConfigFromDirectives(policy.Statements)
		if err != nil {
			t.Fatal("canonical policy cannot be reparsed")
		}
		original, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		reencoded, err := json.Marshal(restored)
		if err != nil || string(original) != string(reencoded) {
			t.Fatal("canonical round trip changed policy", err)
		}
		methods := map[string]bool{"password": true, "totp": inventory&1 != 0, "u2f": inventory&2 != 0, "email": inventory&4 != 0}
		methods["mfa"] = methods["totp"] || methods["u2f"] || methods["email"]
		selected := policy.ResolveChallenges(methods)
		seen := map[string]bool{}
		for _, method := range selected {
			if !methods[method] || seen[method] {
				t.Fatal("policy selected an unavailable or duplicate method")
			}
			seen[method] = true
		}
		if len(selected) > 0 {
			selected[0] = "changed"
			if _, err := parser.NewAuthenticationChallengeConfigFromDirectives(policy.Statements); err != nil || policy.Validate() != nil {
				t.Fatal("resolved methods alias the policy")
			}
		}
	})
}

func ExampleNewAuthenticationChallengeConfigFromDirectives() {
	c, err := parser.NewAuthenticationChallengeConfigFromDirectives([]string{"u2f", "password totp if u2f not available", "password if u2f and totp not available"})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.ResolveChallenges(map[string]bool{"totp": true}))
	// Output: [password totp]
}
