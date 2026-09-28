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
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/acl/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewACLFieldConfigFromDirectives(t *testing.T) {
	key := `https://example.org/a.b|c, "quoted" space`
	claim := cfgutil.EncodeArgs([]string{"claim", key})
	for _, tc := range []struct {
		name       string
		statements []string
		kind       string
	}{
		{"string", []string{claim, "type string"}, acl.FieldTypeString},
		{"list", []string{claim, "type string list"}, acl.FieldTypeStringList},
		{"order", []string{"type string list", claim}, acl.FieldTypeStringList},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.statements)
			got, err := parser.NewACLFieldConfigFromDirectives("external", tc.statements)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(&acl.FieldConfig{Name: "external", Claim: key, Type: tc.kind}, got); diff != "" {
				t.Fatal(diff)
			}
			got.Claim = "changed"
			again, err := parser.NewACLFieldConfigFromDirectives("external", tc.statements)
			if err != nil || again.Claim != key {
				t.Fatal("parser results share mutable state")
			}
			if diff := cmp.Diff(before, tc.statements); diff != "" {
				t.Fatal("input changed:", diff)
			}
		})
	}
	for _, statements := range [][]string{
		nil, {}, {claim}, {"type string"}, {claim, "type"}, {"claim", "type string"},
		{claim, "type number"}, {claim, "type string_list"}, {claim, "type list"},
		{claim, "type string list extra"}, {claim, "type String"},
		{claim, "type string", "type string"}, {claim, "type string", "type string list"},
		{claim, "type string", claim}, {claim, "unknown secret-marker"},
		{claim, "type string\nunknown secret-marker"}, {claim, "type string\r"},
		{claim, "type string\x00"}, {`claim "unterminated`, "type string"},
		{`claim,""`, "type string"}, {`claim," ",extra`, "type string"},
		{"claim foo bar", "type string"}, {claim, "type string", ""},
		{"acl field external", claim, "type string"},
	} {
		got, err := parser.NewACLFieldConfigFromDirectives("external", statements)
		if err == nil || got != nil {
			t.Fatalf("invalid statements produced a result: %v", statements)
		}
		if strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), key) {
			t.Fatal("error echoes input")
		}
	}
	for _, name := range []string{"roles", "method", "", "bad secret-marker"} {
		got, err := parser.NewACLFieldConfigFromDirectives(name, []string{claim, "type string"})
		if err == nil || got != nil {
			t.Fatal("invalid field name accepted")
		}
		if strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("error echoes name")
		}
	}
}

func ExampleNewACLFieldConfigFromDirectives() {
	field, err := parser.NewACLFieldConfigFromDirectives("external_roles", []string{
		cfgutil.EncodeArgs([]string{"claim", "https://example.org/roles"}),
		cfgutil.EncodeArgs([]string{"type", "string", "list"}),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(field.Name, field.Claim, field.Type)
	// Output: external_roles https://example.org/roles string_list
}
