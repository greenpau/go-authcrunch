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

package transformer

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"testing"
)

func TestFactory(t *testing.T) {
	var testcases = []struct {
		name    string
		configs []*Config
		user    map[string]interface{}
		keys    []string
		// Expected results.
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "add authp/admin role to greenpau@outlook.com",
			user: map[string]interface{}{
				"email": "greenpau@outlook.com",
				"roles": "editor",
			},
			keys: []string{
				"challenges",
				"roles",
			},
			configs: []*Config{
				{
					Matchers: []string{
						"exact match email greenpau@outlook.com",
					},
					Actions: []string{
						"add role authp/admin authp/viewer",
						"add role authp/editor",
						"require mfa",
					},
				},
			},
			want: map[string]interface{}{
				"roles": []string{
					"editor",
					"authp/admin",
					"authp/viewer",
					"authp/editor",
				},
				"challenges": []string{
					"mfa",
				},
			},
		},
		{
			name: "drop existing authp/viewer role",
			user: map[string]interface{}{
				"email": "greenpau@outlook.com",
				"roles": []string{"authp/admin", "authp/editor", "authp/viewer"},
			},
			keys: []string{
				"roles",
			},
			configs: []*Config{
				{
					Matchers: []string{
						"regex match role viewer",
					},
					Actions: []string{
						"action drop matched role",
					},
				},
			},
			want: map[string]interface{}{
				"roles": []string{
					"authp/admin",
					"authp/editor",
				},
			},
		},
		{
			name: "drop any role without words authp/admin or authp/user",
			user: map[string]interface{}{
				"email": "greenpau@outlook.com",
				"roles": []string{
					"authp/admin",
					"authp/editor",
					"authp/viewer",
					"authp/user",
				},
			},
			keys: []string{
				"roles",
			},
			configs: []*Config{
				{
					Matchers: []string{
						"no regex match any role ^authp/(admin|user)$",
					},
					Actions: []string{
						"action drop matched role",
					},
				},
			},
			want: map[string]interface{}{
				"roles": []string{
					"authp/admin",
					"authp/user",
				},
			},
		},
		{
			name: "drop any role without words authp/admin or authp/user and no roles found",
			user: map[string]interface{}{
				"email": "greenpau@outlook.com",
				"roles": []string{"authp/editor"},
			},
			keys: []string{
				"roles",
			},
			configs: []*Config{
				{
					Matchers: []string{
						"no regex match any role ^authp/(admin|user)$",
					},
					Actions: []string{
						"action drop matched role",
					},
				},
			},
			want: map[string]interface{}{
				"roles": []string(nil),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			tr, err := NewFactory(tc.configs)
			if err != nil {
				if tests.EvalErrWithLog(t, err, "transformer", tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			if err := tr.Transform(tc.user, nil); err != nil {
				if tests.EvalErrWithLog(t, err, "transformer", tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			got := make(map[string]interface{})
			for _, k := range tc.keys {
				if v, exists := tc.user[k]; exists {
					got[k] = v
				}
			}
			tests.EvalObjectsWithLog(t, "transformer", tc.want, got, msgs)
		})
	}
}

func TestTransformData(t *testing.T) {
	var testcases = []struct {
		name      string
		args      []string
		matcher   *acl.AccessList
		user      map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "add role authp/user with webadmin",
			args: []string{"add", "role", "authp/user"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin"},
			},
			want: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
		},
		{
			name: "add add _couchdb.roles _admin with webadmin",
			args: []string{"add", "_couchdb.roles", "_admin", "as", "string", "list"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			want: map[string]interface{}{
				"sub":            "webadmin",
				"roles":          []interface{}{string("authp/admin"), string("authp/user")},
				"_couchdb.roles": []string{"_admin"},
			},
		},
		{
			name: "add add _couchdb.db _admin with webadmin",
			args: []string{"add", "_couchdb.db", "accounts", "as", "string"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			want: map[string]interface{}{
				"sub":         "webadmin",
				"roles":       []interface{}{string("authp/admin"), string("authp/user")},
				"_couchdb.db": "accounts",
			},
		},
		{
			name: "as type directive is too short",
			args: []string{"add", "_couchdb.roles", "_admin", "as"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			shouldErr: true,
			err: fmt.Errorf(
				"failed transforming %q field for %q action in %v: %v",
				"_couchdb.roles", "add", []string{"add", "_couchdb.roles", "_admin", "as"},
				"as type directive is too short",
			),
		},
		{
			name: "unsupported data type",
			args: []string{"add", "_couchdb.roles", "_admin", "as", "foo"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			shouldErr: true,
			err: fmt.Errorf(
				"failed transforming %q field for %q action in %v: %v",
				"_couchdb.roles", "add", []string{"add", "_couchdb.roles", "_admin", "as", "foo"},
				"unsupported \"foo\" data type",
			),
		},
		{
			name: "add matrix_id claim with replacer from sub claim",
			args: []string{"add", "matrix_id", "@{claims.sub}:matrix.foo.bar", "as", "string"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin"},
			},
			want: map[string]interface{}{
				"sub":       "webadmin",
				"roles":     []interface{}{"authp/admin"},
				"matrix_id": "@webadmin:matrix.foo.bar",
			},
		},
		{
			name: "add matrix_id claim with replacer from sub and email claims",
			args: []string{"add", "matrix_id", "@{claims.sub}:{claims.email}:matrix.foo.bar", "as", "string"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"email": "webadmin@localdomain.local",
				"roles": []string{"authp/admin"},
			},
			want: map[string]interface{}{
				"sub":       "webadmin",
				"roles":     []interface{}{"authp/admin"},
				"email":     "webadmin@localdomain.local",
				"matrix_id": "@webadmin:webadmin@localdomain.local:matrix.foo.bar",
			},
		},
		{
			name: "add roles based on replacer from realm claim",
			args: []string{
				"add", "roles", "{claims.realm}/admin", "{claims.realm}/user"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"realm": "local",
				"email": "webadmin@localdomain.local",
				"roles": []string{"authp/admin"},
			},
			want: map[string]interface{}{
				"sub":   "webadmin",
				"realm": "local",
				"roles": []string{"authp/admin", "local/admin", "local/user"},
				"email": "webadmin@localdomain.local",
			},
		},
		{
			name: "add email claim based on replacer from sub and realm claims",
			args: []string{
				"add", "email", "{claims.sub}@{claims.realm}"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"realm": "localdomain.local",
				"roles": []string{"authp/admin"},
			},
			want: map[string]interface{}{
				"sub":   "webadmin",
				"realm": "localdomain.local",
				"roles": []interface{}{"authp/admin"},
				"email": "webadmin@localdomain.local",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			got := deepCopy(tc.user)
			if err := transformData(tc.args, got, tc.matcher); err != nil {
				if tests.EvalErrWithLog(t, err, "transformer", tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			tests.EvalObjectsWithLog(t, "transformer", tc.want, got, msgs)
		})
	}
}

func TestFactoryAuthChallenges(t *testing.T) {
	// Rules from greenpau/caddy-security#470 example chain, exercised across
	// user populations below.
	issue470Rules := []string{
		"require auth challenges u2f",
		"require auth challenges password totp if u2f not available",
		"require auth challenges password if u2f and totp not available",
	}
	testcases := []struct {
		name            string
		configs         []*Config
		user            map[string]interface{}
		userAuthMethods []string
		want            map[string]interface{}
		shouldErr       bool
	}{
		{
			name: "conditional rule matches when condition absent",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "totp"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  []string{"require auth challenges password totp if u2f not available"},
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"password", "totp"},
			},
		},
		{
			name: "conditional rule skipped when condition present then unconditional matches",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "u2f"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions: []string{
						"require auth challenges password totp if u2f not available",
						"require auth challenges u2f",
					},
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"u2f"},
			},
		},
		{
			name: "rule gate excludes unreachable challenge then later rule matches",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions: []string{
						"require auth challenges totp if u2f not available",
						"require auth challenges password if u2f and totp not available",
					},
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"password"},
			},
		},
		{
			name: "all rules fail returns error",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "u2f"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions: []string{
						"require auth challenges totp if u2f not available",
						"require auth challenges password if u2f and totp not available",
					},
				},
			},
			shouldErr: true,
		},
		{
			name: "auth challenges coexists with require mfa",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "totp"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions: []string{
						"require mfa",
						"require auth challenges totp if u2f not available",
					},
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"mfa", "totp"},
			},
		},
		{
			name: "malformed auth challenges rule returns error",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: nil,
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  []string{"require auth challenges u2f if"},
				},
			},
			shouldErr: true,
		},
		{
			name: "#470 example: u2f user wins rule 1",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "u2f"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  issue470Rules,
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"u2f"},
			},
		},
		{
			name: "#470 example: totp user wins rule 2",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "totp"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  issue470Rules,
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"password", "totp"},
			},
		},
		{
			name: "#470 example: password-only user wins rule 3",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  issue470Rules,
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"password"},
			},
		},
		{
			name: "federated user with nil AuthMethods and MFA rule errors",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: nil,
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  []string{"require auth challenges totp if u2f not available"},
				},
			},
			shouldErr: true,
		},
		{
			name: "federated user with nil AuthMethods and password-only rule passes",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: nil,
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  []string{"require auth challenges password"},
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"password"},
			},
		},
		{
			name: "#470 example: multi-MFA user (u2f+totp) wins rule 1",
			user: map[string]interface{}{
				"email": "user@example.com",
			},
			userAuthMethods: []string{"password", "u2f", "totp"},
			configs: []*Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  issue470Rules,
				},
			},
			want: map[string]interface{}{
				"challenges": []string{"u2f"},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			tr, err := NewFactory(tc.configs)
			if err != nil {
				if tc.shouldErr {
					return
				}
				t.Fatalf("NewFactory: %v", err)
			}
			err = tr.Transform(tc.user, tc.userAuthMethods)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := map[string]interface{}{}
			if v, exists := tc.user["challenges"]; exists {
				got["challenges"] = v
			}
			tests.EvalObjectsWithLog(t, "challenges", tc.want, got, msgs)
		})
	}
}

func BenchmarkFactoryTransform_AuthChallenges(b *testing.B) {
	configs := []*Config{
		{
			Matchers: []string{"exact match email user@example.com"},
			Actions: []string{
				"require auth challenges u2f",
				"require auth challenges password totp if u2f not available",
				"require auth challenges password if u2f and totp not available",
			},
		},
	}
	tr, err := NewFactory(configs)
	if err != nil {
		b.Fatalf("NewFactory: %v", err)
	}
	authMethods := []string{"password", "u2f", "totp"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := map[string]interface{}{"email": "user@example.com"}
		if err := tr.Transform(m, authMethods); err != nil {
			b.Fatalf("Transform: %v", err)
		}
	}
}

func deepCopy(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	j, _ := json.Marshal(src)
	m := make(map[string]interface{})
	json.Unmarshal(j, &m)
	return m
}
