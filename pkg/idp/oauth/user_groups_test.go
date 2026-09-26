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

package oauth

import (
	"reflect"
	"testing"
)

func TestDecodeGoogleUserGroupsRejectsUnsafeTypes(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
		wantErr    bool
	}{
		{
			name: "valid groups",
			body: `{"response":{"groups":[{"displayName":"engineering"},{"displayName":"operators"}]}}`,
			want: []string{"engineering", "operators"},
		},
		{name: "empty response", body: `{}`, want: []string{}},
		{name: "numeric display name", body: `{"response":{"groups":[{"displayName":7}]}}`, wantErr: true},
		{name: "missing display name", body: `{"response":{"groups":[{}]}}`, wantErr: true},
		{name: "empty display name", body: `{"response":{"groups":[{"displayName":" "}]}}`, wantErr: true},
		{name: "malformed JSON", body: `{`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeGoogleUserGroups([]byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("decodeGoogleUserGroups() = %#v, %v; want error %t", got, err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("groups = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestMergeGoogleUserGroupsIsAtomic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		roles   any
		exists  bool
		want    any
		wantErr bool
	}{
		{name: "no existing roles", want: []string{"engineering"}},
		{name: "string roles", roles: []string{"viewer"}, exists: true, want: []string{"viewer", "engineering"}},
		{name: "decoded roles", roles: []any{"viewer"}, exists: true, want: []string{"viewer", "engineering"}},
		{name: "numeric decoded role", roles: []any{"viewer", 7}, exists: true, wantErr: true},
		{name: "scalar roles", roles: "viewer", exists: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userData := map[string]any{}
			if tc.exists {
				userData["roles"] = tc.roles
			}
			before := userData["roles"]
			err := mergeGoogleUserGroups(userData, []string{"engineering"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("mergeGoogleUserGroups() error = %v, want error %t", err, tc.wantErr)
			}
			if tc.wantErr {
				if !reflect.DeepEqual(userData["roles"], before) {
					t.Fatalf("failed merge mutated roles: %#v", userData["roles"])
				}
				return
			}
			if !reflect.DeepEqual(userData["roles"], tc.want) {
				t.Fatalf("roles = %#v, want %#v", userData["roles"], tc.want)
			}
		})
	}
}
