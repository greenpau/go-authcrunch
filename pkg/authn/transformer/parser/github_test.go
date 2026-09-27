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
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestGithubMatcher(t *testing.T) {
	for _, tc := range []struct {
		name, matcher, id, realm string
		want                     bool
	}{
		{"exact", "match github id exact 12345678", "12345678", "engineering", true},
		{"mismatch", "match github id exact 12345678", "12345679", "engineering", false},
		{"large", "match github id exact 9007199254740993", "9007199254740993", "engineering", true},
		{"large neighbor", "match github id exact 9007199254740993", "9007199254740992", "engineering", false},
		{"maximum", "match github id exact 18446744073709551615", "18446744073709551615", "engineering", true},
		{"regex", "match github id regex ^(12345678|87654321)$", "87654321", "engineering", true},
		{"regex miss", "match github id regex ^(12345678|87654321)$", "112345678", "engineering", false},
		{"unanchored regex", "match github id regex 123", "91234", "engineering", true},
		{"quoted regex", cfgutil.EncodeArgs([]string{"match", "github", "id", "regex", `^(?:123|456)$`}), "456", "engineering", true},
		{"quoted tokens", `"match" "github" "id" "exact" "123"`, "123", "engineering", true},
		{"AND semantics", "match github id exact 12345678", "12345678", "other", false},
		{"missing", "match github id regex .*", "", "engineering", false},
		{"ordinary ACL spelling", "exact match github_id 123", "123", "engineering", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statements := []string{tc.matcher, "match realm engineering", "action add role github-member"}
			original := slices.Clone(statements)
			cfg, err := parser.NewUserTransformerConfigFromDirectives(statements)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(statements, original) {
				t.Fatal("parser changed its input")
			}
			encoded, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var restored transformer.Config
			if err := json.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			before := slices.Clone(restored.Matchers)
			compiled, err := parser.CompileUserTransformerConfig(&restored)
			if err != nil || compiled == nil {
				t.Fatal("compile failed", err)
			}
			if !slices.Equal(restored.Matchers, before) {
				t.Fatal("compiler changed serialized matchers")
			}
			factory, err := transformer.NewFactory([]*transformer.Config{&restored})
			if err != nil {
				t.Fatal(err)
			}
			restored.Matchers[0] = "match sub different"
			restored.Actions[0] = "deny"
			cfg.Matchers[0] = "match sub different"
			claims := map[string]any{"realm": tc.realm, "metadata": map[string]any{"id": 12345678}}
			if tc.id != "" {
				claims["github_id"] = tc.id
			}
			if err := factory.Transform(claims); err != nil {
				t.Fatal(err)
			}
			got, _ := claims["roles"].([]string)
			if slices.Contains(got, "github-member") != tc.want {
				t.Fatalf("roles = %v; want match %t", got, tc.want)
			}
		})
	}
}

func TestGithubMatcherRejectsInvalidConfiguration(t *testing.T) {
	invalid := []string{
		"match github", "match github id", "match github id exact",
		"match github login exact 123", "match github id partial 123",
		"match github id suffix 123", "match github id EXACT 123",
		"match github id exact 123 extra", "match github id regex ^123$ extra",
		"match github id exact 0", "match github id exact -1", "match github id exact +1",
		"match github id exact 001", "match github id exact 1.0", "match github id exact 1e3",
		"match github id exact 18446744073709551616", "match github id exact private-marker",
		"match github id regex (private-marker", `match github id exact ""`,
		`match github id regex " "`, "match github id exact 123\nadd role admin",
		"match github id exact 123\radd role admin", "match github id regex [",
		"match github org", "match github org exact", "match github org partial acme",
		"match github org regex [", "match github org exact acme extra",
		`match github org exact ""`,
		"exact match github id exact 123", "no match github id exact 123",
	}
	for _, statement := range invalid {
		t.Run(statement, func(t *testing.T) {
			cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{statement, "add role member"})
			if err == nil || cfg != nil {
				t.Fatal("invalid directive accepted")
			}
			compiled, err := parser.CompileUserTransformerConfig(&transformer.Config{Matchers: []string{statement}, Actions: []string{"add role member"}})
			if err == nil || compiled != nil {
				t.Fatal("invalid typed matcher accepted")
			}
			if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("raw input disclosed")
			}
		})
	}
	if cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{
		"match github id exact 123", "match github id regex ^123$", "add role member",
	}); err == nil || cfg != nil {
		t.Fatal("duplicate field matcher accepted")
	}
}

func TestGithubIDIsProviderOwned(t *testing.T) {
	for _, action := range []string{
		"add github_orgs acme", "overwrite github_orgs acme", "delete github_orgs",
		"action add github_orgs acme", "add nested github_orgs as map",
		"add github_id 123", "overwrite github_id 123", "delete github_id",
		"add github_id 123 as string", "action add github_id 123", "action overwrite github_id 123",
		"action delete github_id", "add nested github_id with 123 as string",
		"add nested github_id as map", "action add nested github_id ignored with 123 as string",
	} {
		t.Run(action, func(t *testing.T) {
			cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", action})
			if err == nil || cfg != nil {
				t.Fatal("provider claim mutation accepted")
			}
			compiled, err := parser.CompileUserTransformerConfig(&transformer.Config{Matchers: []string{"match realm local"}, Actions: []string{action}})
			if err == nil || compiled != nil {
				t.Fatal("typed provider claim mutation accepted")
			}
		})
	}
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match github id exact 123", "add account {claims.github_id} as string"})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"github_id": "123"}
	if err := factory.Transform(claims); err != nil || claims["account"] != "123" {
		t.Fatal("ID substitution failed", err)
	}
	for _, value := range []any{nil, 123, float64(123), json.Number("123"), []string{"123"}, map[string]any{}, "", "0", "-1", "001", "1.5", "private-marker", "18446744073709551616"} {
		input := map[string]any{"github_id": value, "roles": []string{"existing"}}
		expected := map[string]any{"github_id": value, "roles": []string{"existing"}}
		if err := factory.Transform(input); err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("invalid ID was not safely rejected")
		}
		if !reflect.DeepEqual(input, expected) {
			t.Fatal("invalid ID changed claims")
		}
	}
}

func ExampleNewUserTransformerConfigFromDirectives_github() {
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{
		"match github id exact 12345678",
		"action add role github-member",
	})
	if err != nil {
		panic(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		panic(err)
	}
	// Embedders must supply claims from the authenticated GitHub provider.
	claims := map[string]any{"github_id": "12345678"}
	err = factory.Transform(claims)
	fmt.Println(claims["roles"], err)
	// Output: [github-member] <nil>
}

func TestGithubOrganizationMatcher(t *testing.T) {
	for _, tc := range []struct {
		name, matcher string
		orgs          any
		want          bool
	}{
		{"exact", "match github org exact acme", []string{"other", "acme"}, true},
		{"exact miss", "match github org exact acme", []string{"acme-labs"}, false},
		{"case sensitive", "match github org exact acme", []string{"ACME"}, false},
		{"regex", "match github org regex ^acme(-labs)?$", []string{"other", "acme-labs"}, true},
		{"regex miss", "match github org regex ^acme$", []string{"my-acme"}, false},
		{"JSON list", "match github org exact acme", []any{"acme"}, true},
		{"empty", "match github org regex .*", []string{}, false},
		{"absent", "match github org regex .*", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{tc.matcher, "match github id exact 123", "add role member"})
			if err != nil {
				t.Fatal(err)
			}
			factory, err := transformer.NewFactory([]*transformer.Config{cfg})
			if err != nil {
				t.Fatal(err)
			}
			claims := map[string]any{"github_id": "123", "roles": []string{"github.com/acme/members"}}
			if tc.orgs != nil {
				claims["github_orgs"] = tc.orgs
			}
			if err := factory.Transform(claims); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(claims["roles"].([]string), "member") != tc.want {
				t.Fatal("unexpected org match result")
			}
			// Both matchers must pass; organization membership cannot bypass ID.
			claims["github_id"] = "124"
			claims["roles"] = []string{}
			if err := factory.Transform(claims); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(claims["roles"].([]string), "member") {
				t.Fatal("org bypassed ID matcher")
			}
		})
	}
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match github org regex .*", "add role member"})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, orgs := range []any{nil, "acme", 123, []any{"acme", 123}, []any{nil}, []string{""}, []string{" "}} {
		if err := factory.Transform(map[string]any{"github_orgs": orgs}); err == nil {
			t.Fatal("invalid org claim accepted")
		}
	}
}

func ExampleNewUserTransformerConfigFromDirectives_githubOrganization() {
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{
		"match github org regex ^(acme|acme-labs)$",
		"action add role organization-member",
	})
	if err != nil {
		panic(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		panic(err)
	}
	claims := map[string]any{"github_orgs": []string{"acme-labs"}}
	err = factory.Transform(claims)
	fmt.Println(claims["roles"], err)
	// Output: [organization-member] <nil>
}
