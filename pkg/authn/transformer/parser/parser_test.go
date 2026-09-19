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

	challengeparser "github.com/greenpau/go-authcrunch/pkg/authchal/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestUserTransformerConfigFromDirectives(t *testing.T) {
	for _, input := range [][]string{nil, {"match realm local"}, {"require mfa"}, {"match realm local", "require"}, {"match realm local", "require auth challenges"}, {"match realm local", "require auth challenges u2f if"}, {"match realm local", "require auth challenges email"}, {"match realm local", "require auth challenges u2f", "require auth challenges u2f"}, {"match realm local\nrequire mfa"}, {"unknown private-marker"}, {cfgutil.EncodeArgs([]string{"match realm", "local"}), "require mfa"}} {
		c, err := parser.NewUserTransformerConfigFromDirectives(input)
		if err == nil || c != nil {
			t.Fatalf("invalid configuration accepted: %q", input)
		}
		if strings.Contains(err.Error(), "private-marker") {
			t.Fatal("raw input disclosed")
		}
	}
	input := []string{"match realm local", cfgutil.EncodeArgs([]string{"overwrite", "name", "Alice Example"}), "require auth challenges password"}
	c, err := parser.NewUserTransformerConfigFromDirectives(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var restored transformer.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{&restored})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"realm": "local"}
	selected, err := factory.TransformWithAuthMethods(claims, []string{"password"})
	if err != nil || fmt.Sprint(selected) != "[password]" || claims["name"] != "Alice Example" {
		t.Fatal("configuration did not survive round trip", err)
	}
	c.Actions[0] = "changed"
	if input[1] != cfgutil.EncodeArgs([]string{"overwrite", "name", "Alice Example"}) {
		t.Fatal("parser retained input")
	}
}

func FuzzUserTransformerAuthenticationChallenges(f *testing.F) {
	for _, statement := range []string{"password", "u2f or totp", "totp password", "password if u2f and totp not available", "u2f if", "u2f\nrequire password", "mfa"} {
		f.Add(statement, uint8(0))
	}
	f.Fuzz(func(t *testing.T, statement string, inventory uint8) {
		if len(statement) > 4096 {
			t.Skip()
		}
		cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"exact match realm local", "require auth challenges " + statement})
		if err != nil {
			if cfg != nil {
				t.Fatal("invalid input returned a partial configuration")
			}
			return
		}
		policy, err := challengeparser.NewAuthenticationChallengeConfigFromDirectives([]string{statement})
		if err != nil {
			t.Fatal("transformer accepted a rule rejected by the owning parser")
		}
		factory, err := transformer.NewFactory([]*transformer.Config{cfg})
		if err != nil {
			t.Fatal("parsed configuration cannot construct a runtime")
		}
		methods := []string{"password"}
		registered := map[string]bool{"password": true}
		for i, method := range []string{"totp", "u2f"} {
			if inventory&(1<<i) != 0 {
				methods = append(methods, method)
				registered[method] = true
			}
		}
		// Mutable claims must not override the separate backend inventory.
		claims := map[string]any{"realm": "local", "auth_methods": []string{"u2f", "totp"}, "challenges": []string{"password"}}
		selected, err := factory.TransformWithAuthMethods(claims, methods)
		want := policy.ResolveChallenges(registered)
		if (err != nil) != (len(want) == 0) || !slices.Equal(selected, want) {
			t.Fatal("transformer and rule parser disagree")
		}
		if _, ok := claims["auth_methods"]; ok {
			t.Fatal("transformer leaked registered methods")
		}
	})
}

func ExampleNewUserTransformerConfigFromDirectives() {
	c, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "require auth challenges u2f", "require auth challenges password if u2f not available"})
	if err != nil {
		panic(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{c})
	if err != nil {
		panic(err)
	}
	selected, err := factory.TransformWithAuthMethods(map[string]any{"realm": "local"}, []string{"password"})
	fmt.Println(selected, err)
	// Output: [password] <nil>
}

func TestCompileUserTransformerConfig(t *testing.T) {
	for _, c := range []*transformer.Config{nil, {}, {Matchers: []string{"match realm local"}, Actions: []string{"deny extra"}}, {Matchers: []string{"match realm local\nmatch sub alice"}, Actions: []string{"deny"}}, {Matchers: []string{"match realm local"}, Actions: []string{"action delete name extra"}}, {Matchers: []string{"match realm local"}, Actions: []string{"action add"}}} {
		compiled, err := parser.CompileUserTransformerConfig(c)
		if err == nil || compiled != nil {
			t.Fatal("invalid serialized config accepted")
		}
	}
	c := &transformer.Config{Matchers: []string{"match realm local"}, Actions: []string{"action delete name", "require auth challenges password"}}
	factory, err := transformer.NewFactory([]*transformer.Config{c})
	if err != nil {
		t.Fatal(err)
	}
	c.Actions[1] = "deny"
	c.Matchers[0] = "match realm other"
	claims := map[string]any{"realm": "local", "name": "removed"}
	if _, err := factory.TransformWithAuthMethods(claims, []string{"password"}); err != nil {
		t.Fatal("caller mutation changed runtime", err)
	}
	if _, ok := claims["name"]; ok {
		t.Fatal("delete action failed")
	}
}

func TestUserTransformerMatcherAndActionBoundaries(t *testing.T) {
	for _, action := range []string{"drop matched roles", "drop matched role extra", "action drop matched", `overwrite name " "`, `delete " "`} {
		if c, err := parser.NewUserTransformerConfigFromDirectives([]string{"match any", action}); err == nil || c != nil {
			t.Fatalf("invalid action accepted: %q", action)
		}
	}
	c, err := parser.NewUserTransformerConfigFromDirectives([]string{"field name exists", "overwrite name Selected"})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{c})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"name": "Alice"}
	if err := factory.Transform(claims); err != nil || claims["name"] != "Selected" {
		t.Fatal("field matcher was not applied", err)
	}
}
