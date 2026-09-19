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
	"strings"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
)

func TestUserTransformerCustomFieldValidation(t *testing.T) {
	for _, action := range []string{
		"add nested meta tag with as string",
		"add nested with marker as string",
		"add nested meta tag with one two as string",
		"add nested meta tag with as list",
		"add nested meta tag with value as map",
		"add custom marker",
		"add custom one two as string",
		"add custom marker as unsupported-private-marker",
		"overwrite custom marker",
	} {
		t.Run(action, func(t *testing.T) {
			input := []string{"match any", action, "require auth challenges password"}
			if cfg, err := parser.NewUserTransformerConfigFromDirectives(input); err == nil || cfg != nil {
				t.Error("invalid custom action passed directive validation")
			} else if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("parser disclosed input")
			}
			cfg := &transformer.Config{Matchers: []string{"match any"}, Actions: []string{action}}
			if runtime, err := parser.CompileUserTransformerConfig(cfg); err == nil || runtime != nil {
				t.Error("invalid custom action passed typed configuration validation")
			} else if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("compiler disclosed input")
			}
		})
	}
}

func TestParseCustomFieldValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		want   any
		failed bool
	}{
		{"scalar", []string{"Alice Example", "as", "string"}, "Alice Example", false},
		{"list", []string{"one", "two", "as", "list"}, []string{"one", "two"}, false},
		{"string list", []string{"one", "two", "as", "string", "list"}, []string{"one", "two"}, false},
		{"legacy type", []string{"one", "as", "string_list"}, []string{"one"}, false},
		{"empty", nil, nil, true},
		{"empty value", []string{"", "as", "string"}, nil, true},
		{"missing type", []string{"one", "as"}, nil, true},
		{"map", []string{"one", "as", "map"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.ParseCustomFieldValues(tc.args)
			if (err != nil) != tc.failed || !reflect.DeepEqual(result, tc.want) {
				t.Fatal("unexpected custom field parse", err)
			}
			if values, ok := result.([]string); ok {
				values[0] = "changed"
				if tc.args[0] == "changed" {
					t.Fatal("parser retained input")
				}
			}
		})
	}
}

func TestParseCustomNestedFieldValues(t *testing.T) {
	for _, tc := range []struct {
		statement string
		path      []string
		value     any
		failed    bool
	}{
		{"client flow with totp as string", []string{"client", "flow"}, "totp", false},
		{"client scopes with read write as string list", []string{"client", "scopes"}, []string{"read", "write"}, false},
		{"client as map", []string{"client"}, map[string]any{}, false},
		{"client flow with as string", nil, nil, true},
		{"client flow with as list", nil, nil, true},
		{"client flow with one two as string", nil, nil, true},
		{"with one as string", nil, nil, true},
		{"client with value as map", nil, nil, true},
		{"client flow as string", nil, nil, true},
		{"client flow with one as", nil, nil, true},
		{"client flow with one as private-marker", nil, nil, true},
	} {
		t.Run(tc.statement, func(t *testing.T) {
			args, err := cfgutil.DecodeArgs(tc.statement)
			if err != nil {
				t.Fatal(err)
			}
			path, value, err := parser.ParseCustomNestedFieldValues(args)
			if (err != nil) != tc.failed || !reflect.DeepEqual(path, tc.path) || !reflect.DeepEqual(value, tc.value) {
				t.Fatal("unexpected nested field parse", err)
			}
			if err != nil && strings.Contains(err.Error(), "private-marker") {
				t.Fatal("parser disclosed raw input")
			}
			if len(path) > 0 {
				path[0] = "changed"
				if args[0] == "changed" {
					t.Fatal("parser retained path")
				}
			}
		})
	}
}

func ExampleNewUserTransformerConfigFromDirectives_customClaims() {
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{
		"match realm local", "add display_name {claims.name} as string",
		"add nested client flow with totp as string", "require auth challenges totp",
	})
	if err != nil {
		panic(err)
	}
	f, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		panic(err)
	}
	claims := map[string]any{"realm": "local", "name": "Alice Example"}
	selected, err := f.TransformWithAuthMethods(claims, []string{"password", "totp"})
	if err != nil {
		panic(err)
	}
	fmt.Println(selected, claims["display_name"], claims["client"].(map[string]any)["flow"])
	// Output: [totp] Alice Example totp
}

func FuzzUserTransformerCustomFields(f *testing.F) {
	for _, value := range []string{"client flow with totp as string", "roles flow with totp as string", "client with as string", "client as map", "client scopes with read write as list"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "add nested " + value})
		if err != nil {
			if cfg != nil {
				t.Fatal("invalid input returned config")
			}
			return
		}
		factory, err := transformer.NewFactory([]*transformer.Config{cfg})
		if err != nil {
			t.Fatal(err)
		}
		// A valid path can still collide with current claim types. That must
		// return an error, never panic; configuration alone cannot decide it.
		_ = factory.Transform(map[string]any{"realm": "local", "roles": []string{"member"}, "client": map[string]any{"flow": nil}})
	})
}
