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
			if err := tr.Transform(tc.user); err != nil {
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

func deepCopy(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	j, _ := json.Marshal(src)
	m := make(map[string]interface{})
	json.Unmarshal(j, &m)
	return m
}
