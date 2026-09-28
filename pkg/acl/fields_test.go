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

package acl_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch/pkg/acl"
)

const customRolesKey = "https://example.org/roles"

func customList(t *testing.T, kind string, conditions ...string) *acl.AccessList {
	t.Helper()
	list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{{Name: "external", Claim: customRolesKey, Type: kind}})
	if err != nil {
		t.Fatal(err)
	}
	if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: conditions, Action: "allow stop"}); err != nil {
		t.Fatal(err)
	}
	return list
}

func TestACLFieldConfig(t *testing.T) {
	for _, name := range []string{"", "roles", "role", "groups", "aud", "exp", "expires", "method", "http_path", "acl", "match", "any", "with", "to", "bad name", "a.b", "é", "1name", strings.Repeat("a", 129)} {
		t.Run("name/"+name, func(t *testing.T) {
			cfg := &acl.FieldConfig{Name: name, Claim: "claim", Type: acl.FieldTypeString}
			if cfg.Validate() == nil {
				t.Fatal("invalid field name accepted")
			}
		})
	}
	for _, claim := range []string{"", " claim", "claim ", "claim\n", "claim\x00", "bad\xff"} {
		cfg := &acl.FieldConfig{Name: "custom", Claim: claim, Type: acl.FieldTypeString}
		if cfg.Validate() == nil {
			t.Fatal("invalid claim key accepted")
		}
	}
	for _, kind := range []string{"", "list", "string list", "number", "boolean"} {
		cfg := &acl.FieldConfig{Name: "custom", Claim: "claim", Type: kind}
		if cfg.Validate() == nil {
			t.Fatal("unsupported field type accepted")
		}
	}
	if (*acl.FieldConfig)(nil).Validate() == nil {
		t.Fatal("nil field accepted")
	}
	valid := &acl.FieldConfig{Name: "custom_1-name", Claim: "https://example.org/a.b/c|d, e", Type: acl.FieldTypeStringList}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, fields := range [][]*acl.FieldConfig{{nil}, {valid, valid}} {
		if list, err := acl.NewAccessListWithFields(fields); err == nil || list != nil {
			t.Fatal("invalid declarations produced an access list")
		}
	}
	for _, fields := range [][]*acl.FieldConfig{nil, {}} {
		if _, err := acl.NewAccessListWithFields(fields); err != nil {
			t.Fatal(err)
		}
	}
}

func TestACLFieldRejectsNullRule(t *testing.T) {
	for _, fields := range [][]*acl.FieldConfig{nil, {{Name: "external", Claim: customRolesKey, Type: acl.FieldTypeStringList}}} {
		list, err := acl.NewAccessListWithFields(fields)
		if err != nil {
			t.Fatal(err)
		}
		if err := list.AddRule(t.Context(), nil); err == nil {
			t.Fatal("null rule accepted")
		}
		if len(list.GetRules()) != 0 || list.Allow(t.Context(), map[string]any{"roles": []string{"admin"}}) {
			t.Fatal("rejected rule changed ACL state")
		}
		if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match roles admin"}, Action: "allow stop"}); err != nil {
			t.Fatal(err)
		}
		if err := list.AddRules(t.Context(), []*acl.RuleConfiguration{nil}); err == nil {
			t.Fatal("null rule in collection accepted")
		}
		if len(list.GetRules()) != 1 || !list.Allow(t.Context(), map[string]any{"roles": []string{"admin"}}) {
			t.Fatal("rejected rule changed existing rules")
		}
	}
}

func TestACLFieldMatchers(t *testing.T) {
	strategies := []struct{ name, expression string }{
		{"exact", "admin"}, {"partial", "dmi"}, {"prefix", "adm"}, {"suffix", "min"}, {"regex", "^admin$"},
	}
	for _, strategy := range strategies {
		for _, kind := range []string{acl.FieldTypeString, acl.FieldTypeStringList} {
			for _, negative := range []bool{false, true} {
				for _, many := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/negative=%t/many=%t", strategy.name, kind, negative, many), func(t *testing.T) {
						condition := strategy.name + " match external " + strategy.expression
						if many {
							condition += " nomatch"
						}
						if negative {
							condition = "no " + condition
						}
						list := customList(t, kind, condition)
						for _, text := range []string{"admin", "reader"} {
							var value any = text
							if kind == acl.FieldTypeStringList {
								value = []any{text}
								if !many {
									value = []string{text}
								}
							}
							want := (text == "admin") != negative
							if got := list.AllowWithClaims(t.Context(), nil, map[string]any{customRolesKey: value}); got != want {
								t.Fatalf("claim match = %t, want %t", got, want)
							}
							if got := list.Allow(t.Context(), map[string]any{"external": value}); got != want {
								t.Fatalf("direct match = %t, want %t", got, want)
							}
						}
					})
				}
			}
		}
	}
}

func TestACLFieldMissingEmptyAndMalformed(t *testing.T) {
	for _, condition := range []string{"match external admin", "no match external admin", "no regex match any external ^admin$"} {
		list := customList(t, acl.FieldTypeStringList, condition)
		for _, claims := range []map[string]any{nil, {}, {customRolesKey: []any{}}, {customRolesKey: []string{}}} {
			if list.AllowWithClaims(t.Context(), nil, claims) {
				t.Fatalf("missing or empty claim granted %q", condition)
			}
		}
	}
	for _, condition := range []string{"field external exists", "field external not exists"} {
		list := customList(t, acl.FieldTypeStringList, condition)
		for _, tc := range []struct {
			value  map[string]any
			exists bool
		}{
			{nil, false}, {map[string]any{customRolesKey: []string{}}, true}, {map[string]any{customRolesKey: []any{"admin"}}, true},
		} {
			want := tc.exists != strings.Contains(condition, "not")
			if got := list.AllowWithClaims(t.Context(), nil, tc.value); got != want {
				t.Fatalf("existence match = %t, want %t", got, want)
			}
		}
	}
	for _, kind := range []string{acl.FieldTypeString, acl.FieldTypeStringList} {
		for _, earlierAllow := range []bool{false, true} {
			list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{{Name: "external", Claim: customRolesKey, Type: kind}})
			if err != nil {
				t.Fatal(err)
			}
			list.SetDefaultAllowAction()
			if earlierAllow {
				if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match roles admin"}, Action: "allow stop"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match external blocked"}, Action: "deny stop"}); err != nil {
				t.Fatal(err)
			}
			bad := []any{nil, 3, true, map[string]any{}, []any{"admin", 3}, []any{"admin", nil}, []string(nil), []any(nil)}
			if kind == acl.FieldTypeString {
				bad = append(bad, []any{"admin"})
			} else {
				bad = append(bad, "admin")
			}
			for _, value := range bad {
				if list.AllowWithClaims(t.Context(), map[string]any{"roles": []string{"admin"}}, map[string]any{customRolesKey: value}) {
					t.Fatal("malformed claim bypassed a deny rule")
				}
				if list.Allow(t.Context(), map[string]any{"roles": []string{"admin"}, "external": value}) {
					t.Fatal("malformed direct input bypassed a deny rule")
				}
			}
		}
	}
	list := customList(t, acl.FieldTypeString, "regex match external ^$")
	if !list.AllowWithClaims(t.Context(), nil, map[string]any{customRolesKey: ""}) {
		t.Fatal("empty scalar is a valid string")
	}
}

func TestACLFieldIsolationAndInputPreservation(t *testing.T) {
	field := &acl.FieldConfig{Name: "external", Claim: customRolesKey, Type: acl.FieldTypeStringList}
	list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{field, {Name: "unused", Claim: "secret", Type: acl.FieldTypeString}})
	if err != nil {
		t.Fatal(err)
	}
	field.Name, field.Claim, field.Type = "changed", "changed", "changed"
	core, logs := observer.New(zap.InfoLevel)
	list.SetLogger(zap.New(core))
	if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match external admin", "match aud app", "match scopes read"}, Action: "allow stop log info"}); err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{customRolesKey: []any{"admin"}, "aud": "app", "scopes": "read write", "secret": map[string]any{"nested": "not-for-acl"}}
	data := map[string]any{"aud": []string{"app"}, "scopes": []string{"read", "write"}}
	snapshot := func(value map[string]any) string {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	wantClaims, wantData := snapshot(claims), snapshot(data)
	if !list.AllowWithClaims(t.Context(), data, claims) {
		t.Fatal("custom or standard normalization lost")
	}
	logged := logs.All()[0].ContextMap()["user"].(map[string]any)
	if _, ok := logged["unused"]; ok {
		t.Fatal("unused claim projected")
	}
	if _, ok := logged["secret"]; ok {
		t.Fatal("unrelated claim projected")
	}
	if _, ok := logged[customRolesKey]; ok {
		t.Fatal("raw source copied into ACL input")
	}
	if diff := cmp.Diff(wantClaims, snapshot(claims)); diff != "" {
		t.Fatal("claims changed:", diff)
	}
	if diff := cmp.Diff(wantData, snapshot(data)); diff != "" {
		t.Fatal("ACL input changed:", diff)
	}
	if field, kind := acl.GetFieldDataType("external"); field != "external" || kind != "" {
		t.Fatal("custom field leaked into global type lookup")
	}
	other := customList(t, acl.FieldTypeString, "match external admin")
	if other.AllowWithClaims(t.Context(), nil, claims) {
		t.Fatal("policy type leaked")
	}
	if err := acl.NewAccessList().AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match external admin"}, Action: "allow stop"}); err == nil {
		t.Fatal("unconfigured field accepted")
	}
	if list.AllowWithClaims(t.Context(), map[string]any{"external": []string{"admin"}, "aud": []string{"app"}, "scopes": []string{"read"}}, nil) {
		t.Fatal("alias substituted for missing source")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 20 {
				if !list.AllowWithClaims(t.Context(), data, claims) || other.AllowWithClaims(t.Context(), nil, claims) {
					t.Error("concurrent policy isolation failed")
				}
			}
		})
	}
	wg.Wait()
}

func TestACLFieldLiteralKeysAndRuleComposition(t *testing.T) {
	key := "https://example.org/a.b|c, d"
	list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{{Name: "external", Claim: key, Type: acl.FieldTypeString}})
	if err != nil {
		t.Fatal(err)
	}
	if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match external admin", "match roles reader"}, Action: "allow any stop"}); err != nil {
		t.Fatal(err)
	}
	if !list.AllowWithClaims(t.Context(), nil, map[string]any{key: "admin"}) {
		t.Fatal("literal key or rule match-any failed")
	}
	if !list.AllowWithClaims(t.Context(), map[string]any{"roles": []string{"reader"}}, nil) {
		t.Fatal("valid alternative rule condition failed")
	}
	if list.AllowWithClaims(t.Context(), nil, map[string]any{"https://example.org/a": map[string]any{"b|c, d": "admin"}}) {
		t.Fatal("claim key treated as a path")
	}
	negative := customList(t, acl.FieldTypeStringList, "no regex match any external ^admin$")
	if !negative.AllowWithClaims(t.Context(), nil, map[string]any{customRolesKey: []any{"admin", "reader"}}) {
		t.Fatal("established negative regex match-any behavior changed")
	}
}
