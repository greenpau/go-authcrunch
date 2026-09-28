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

package authz_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
)

func TestConfigureAccessListFields(t *testing.T) {
	policy := &authz.PolicyConfig{Name: "custom", AuthURLPath: "/login", AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match external admin"}, Action: "allow stop"}}}
	if err := policy.Validate(); err == nil {
		t.Fatal("undeclared field accepted")
	}
	field := &acl.FieldConfig{Name: "external", Claim: "https://example.org/roles", Type: acl.FieldTypeStringList}
	if err := policy.ConfigureAccessListFields([]*acl.FieldConfig{field}); err != nil {
		t.Fatal(err)
	}
	field.Claim = "changed"
	if policy.AccessListFields[0].Claim != "https://example.org/roles" {
		t.Fatal("policy retained caller field")
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range [][]*acl.FieldConfig{{nil}, {field, field}, {{Name: "roles", Claim: "roles", Type: acl.FieldTypeString}}} {
		if err := policy.ConfigureAccessListFields(fields); err == nil {
			t.Fatal("invalid fields accepted")
		}
		after, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("failed application changed policy")
		}
	}
	var restored authz.PolicyConfig
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(policy.AccessListFields, restored.AccessListFields); diff != "" {
		t.Fatal(diff)
	}
	if restored.AuthURLPath != "/login" || len(restored.AccessListRules) != 1 {
		t.Fatal("unrelated settings changed")
	}
	// Public typed callers receive the same checks, even after prior validation.
	policy.AccessListFields[0].Type = "number"
	if err := policy.Validate(); err == nil {
		t.Fatal("revalidation ignored changed field")
	}
	if err := restored.ConfigureAccessListFields(nil); err != nil {
		t.Fatal(err)
	}
	if restored.AccessListFields != nil {
		t.Fatal("nil declarations did not clear fields")
	}
	if err := restored.Validate(); err == nil {
		t.Fatal("revalidation accepted a now-undeclared field")
	}
	if err := (*authz.PolicyConfig)(nil).ConfigureAccessListFields(nil); err == nil {
		t.Fatal("nil policy accepted")
	}
}
