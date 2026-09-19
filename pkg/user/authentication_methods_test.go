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

package user_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestAuthenticationMethods(t *testing.T) {
	for _, input := range []any{[]string{"pwd", "otp", "pwd"}, []any{"pwd", "otp", "pwd"}} {
		u, err := user.NewUser(map[string]any{"sub": "alice", "amr": input})
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []any{u.Claims.AuthenticationMethods, u.AsMap()["amr"], u.GetData()["amr"]} {
			if fmt.Sprint(value) != "[pwd otp]" {
				t.Fatal("method references not preserved")
			}
		}
		clone := u.Clone()
		clone.Claims.AuthenticationMethods[0] = "changed"
		if u.Claims.AuthenticationMethods[0] != "pwd" {
			t.Fatal("claim clone aliases original")
		}
		data, err := json.Marshal(u.AsMap())
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := user.NewUser(data)
		if err != nil {
			t.Fatal(err)
		}
		policy := acl.NewAccessList()
		if err := policy.AddRules(t.Context(), []*acl.RuleConfiguration{{Conditions: []string{"match amr otp"}, Action: "allow stop"}}); err != nil {
			t.Fatal(err)
		}
		if !policy.Allow(t.Context(), parsed.GetData()) {
			t.Fatal("AMR ACL did not authorize verified method")
		}
		passwordOnly, err := user.NewUser(map[string]any{"sub": "alice", "amr": []string{"pwd"}})
		if err != nil {
			t.Fatal(err)
		}
		if policy.Allow(t.Context(), passwordOnly.GetData()) {
			t.Fatal("AMR ACL accepted missing factor")
		}
	}
	for _, input := range []any{"pwd", []any{"pwd", true}, []string{""}, 42, nil} {
		if u, err := user.NewUser(map[string]any{"sub": "alice", "amr": input}); err == nil || u != nil {
			t.Fatal("malformed AMR accepted")
		}
	}
}
