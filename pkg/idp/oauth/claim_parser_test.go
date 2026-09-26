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

package oauth

import (
	"reflect"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestParseCognitoClaimsIsTypedAndAtomic(t *testing.T) {
	for _, tc := range []struct {
		name      string
		claims    jwtlib.MapClaims
		wantRoles []string
		wantData  map[string]any
		wantErr   bool
	}{
		{
			name: "valid claims",
			claims: jwtlib.MapClaims{
				"custom:roles": "editor|operator", "cognito:groups": []any{"engineering"},
				"cognito:roles": "auditor", "zoneinfo": "UTC",
				"custom:timezone": "America/New_York", "cognito:username": "alice",
			},
			wantRoles: []string{"viewer", "editor", "operator", "engineering", "auditor"},
			wantData:  map[string]any{"subject": "alice", "timezone": "America/New_York", "username": "alice"},
		},
		{name: "numeric timezone", claims: jwtlib.MapClaims{"custom:timezone": 7}, wantErr: true},
		{name: "object username", claims: jwtlib.MapClaims{"cognito:username": map[string]any{}}, wantErr: true},
		{name: "array zoneinfo", claims: jwtlib.MapClaims{"zoneinfo": []any{"UTC"}}, wantErr: true},
		{name: "numeric role entry", claims: jwtlib.MapClaims{"cognito:groups": []any{"engineering", 7}}, wantErr: true},
		{name: "object roles", claims: jwtlib.MapClaims{"cognito:roles": map[string]any{}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := map[string]any{"subject": "alice"}
			before := map[string]any{"subject": "alice"}
			roles, err := parseCognitoClaims(tc.claims, parsed, []string{"viewer"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseCognitoClaims() = %v, %v; want error %t", roles, err, tc.wantErr)
			}
			if tc.wantErr {
				if roles != nil || !reflect.DeepEqual(parsed, before) {
					t.Fatalf("failed parse returned roles %v or mutated data %#v", roles, parsed)
				}
				return
			}
			if !reflect.DeepEqual(roles, tc.wantRoles) || !reflect.DeepEqual(parsed, tc.wantData) {
				t.Fatalf("roles/data = %#v/%#v, want %#v/%#v", roles, parsed, tc.wantRoles, tc.wantData)
			}
		})
	}
}
