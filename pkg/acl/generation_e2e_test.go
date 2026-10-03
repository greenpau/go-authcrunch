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

package acl_test

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
)

// Keep migration regressions independent of the generated test matrices.
func TestE2EACLGeneratedConditions(t *testing.T) {
	if field, kind := acl.GetFieldDataType("amr"); field != "amr" || kind != "list_str" {
		t.Fatalf("amr field = %q, %q; want amr, list_str", field, kind)
	}
	testcases := []struct {
		name      string
		condition string
		input     map[string]any
		want      bool
	}{
		{"amr match", "match amr otp", map[string]any{"amr": []string{"pwd", "otp"}}, true},
		{"amr mismatch", "match amr otp", map[string]any{"amr": []string{"pwd"}}, false},
		{"amr missing", "match amr otp", map[string]any{}, false},
		{"any unconditional", "match any", map[string]any{"exp": int64(1)}, true},
		{"any without timestamps", "match any", nil, true},
		{"any exact", "exact match any roles admin", map[string]any{"roles": []string{"admin"}}, true},
		{"any exact mismatch", "exact match any roles admin", map[string]any{"roles": []string{"guest"}}, false},
		{"regex one expression list input", "no regex match any roles ^admin$", map[string]any{"roles": []string{"admin", "guest"}}, true},
		{"regex one expression all match", "no regex match any roles ^admin$", map[string]any{"roles": []string{"admin"}}, false},
		{"regex one expression empty input", "no regex match any roles ^admin$", map[string]any{"roles": []string{}}, false},
		{"regex expression list string input", "no regex match any name ^admin$ ^guest$", map[string]any{"name": "admin"}, true},
		{"regex expression list all match", "no regex match any name ^admin$ ^ad", map[string]any{"name": "admin"}, false},
		{"regex expression list list input", "no regex match any roles ^admin$ ^guest$", map[string]any{"roles": []string{"admin", "guest"}}, true},
		{"regex expression list all pairs match", "no regex match any roles ^admin$ ^ad", map[string]any{"roles": []string{"admin"}}, false},
		{"regex expression list empty input", "no regex match any roles ^admin$ ^guest$", map[string]any{"roles": []string{}}, false},
		{"regex default one expression", "no regex match roles ^admin$", map[string]any{"roles": []string{"admin", "guest"}}, false},
		{"regex default expression list", "no regex match name ^admin$ ^guest$", map[string]any{"name": "admin"}, false},
		{"regex default two lists", "no regex match roles ^admin$ ^guest$", map[string]any{"roles": []string{"admin", "guest"}}, false},
		{"regex default no pairs match", "no regex match roles ^admin$ ^guest$", map[string]any{"roles": []string{"reader"}}, true},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			access := acl.NewAccessList()
			if err := access.AddRule(ctx, &acl.RuleConfiguration{
				Conditions: []string{tc.condition},
				Action:     "allow stop",
			}); err != nil {
				t.Fatal(err)
			}
			if got := access.Allow(ctx, tc.input); got != tc.want {
				t.Fatalf("Allow() = %t; want %t", got, tc.want)
			}
			rules := access.AsMap()["rules"].([]map[string]any)
			conditions := rules[0]["conditions"].([]map[string]any)
			wantAny := strings.Contains(tc.condition, "match any ")
			if got := conditions[0]["match_any"]; got != wantAny {
				t.Fatalf("match_any = %v; want %t", got, wantAny)
			}
		})
	}
}

func TestE2EACLDefaultOrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []*acl.RuleConfiguration
		want  bool
	}{
		{"default allow", []*acl.RuleConfiguration{{Conditions: []string{"match any"}, Action: "allow"}}, true},
		{"default deny overrides allow", []*acl.RuleConfiguration{
			{Conditions: []string{"match roles admin"}, Action: "allow log debug"},
			{Conditions: []string{"match any"}, Action: "deny"},
		}, false},
		{"allow stop precedes default deny", []*acl.RuleConfiguration{
			{Conditions: []string{"match roles admin"}, Action: "allow stop"},
			{Conditions: []string{"match any"}, Action: "deny"},
		}, true},
		{"deny overrides default allow", []*acl.RuleConfiguration{
			{Conditions: []string{"match any"}, Action: "allow"},
			{Conditions: []string{"match roles admin"}, Action: "deny stop"},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access := acl.NewAccessList()
			access.SetLogger(zap.NewNop())
			if err := access.AddRules(t.Context(), tc.rules); err != nil {
				t.Fatal(err)
			}
			data := map[string]any{"roles": []string{"admin"}}
			if got := access.Allow(t.Context(), data); got != tc.want {
				t.Fatalf("Allow() = %t, want %t", got, tc.want)
			}
			if len(data) != 1 {
				t.Fatal("evaluation added claims to caller data")
			}
		})
	}
}
