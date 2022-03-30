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

package ids

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestNewIdentityStoreConfig(t *testing.T) {
	testcases := []struct {
		name      string
		storeName string
		kind      string
		params    map[string]interface{}
		want      string
		shouldErr bool
		err       error
	}{
		{
			name:      "test local identity store",
			storeName: "default",
			kind:      "local",
			params: map[string]interface{}{
				"path":  "foo",
				"realm": "local",
			},
			want: `{
			  "kind": "local",
			  "name": "default",
			  "params": {
			    "path":"foo",
				"realm":"local"
			  }
            }`,
		},
		{
			name:      "test ldap identity store",
			storeName: "contoso.com",
			kind:      "ldap",
			params: map[string]interface{}{
				"realm":              "contoso.com",
				"bind_password":      "P@ssW0rd123",
				"bind_username":      "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
				"search_base_dn":     "DC=CONTOSO,DC=COM",
				"search_user_filter": "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))",
				"attributes": map[string]interface{}{
					"email":     "mail",
					"member_of": "memberOf",
					"name":      "givenName",
					"surname":   "sn",
					"username":  "sAMAccountName",
				},
				"servers": []map[string]interface{}{
					{
						"address":            "ldaps://ldaps.contoso.com",
						"ignore_cert_errors": true,
					},
				},
				"groups": []map[string]interface{}{
					{
						"dn":    "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
						"roles": []string{"admin"},
					},
					{
						"dn":    "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
						"roles": []string{"editor"},
					},
					{
						"dn":    "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
						"roles": []string{"viewer"},
					},
				},
			},
			want: `{
              "name": "contoso.com",
              "kind": "ldap",
              "params": {
                "attributes": {
                  "email": "mail",
                  "member_of": "memberOf",
                  "name": "givenName",
                  "surname": "sn",
                  "username": "sAMAccountName"
                },
                "bind_password": "P@ssW0rd123",
                "bind_username": "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
                "groups": [
                  {
                    "dn": "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                    "roles": ["admin"]
                  },
                  {
                    "dn": "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                    "roles": ["editor"]
                  },
                  {
                    "dn": "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                    "roles": ["viewer"]
                  }
                ],
                "realm": "contoso.com",
                "search_base_dn": "DC=CONTOSO,DC=COM",
                "search_user_filter": "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))",
                "servers": [
                  {
                    "address": "ldaps://ldaps.contoso.com",
                    "ignore_cert_errors": true
                  }
                ]
              }
			}`,
		},
		{
			name:      "test config validation error",
			storeName: "default",
			kind:      "local",
			params: map[string]interface{}{
				"realm": "local",
			},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				fmt.Errorf("required field %q not found", "path"),
			),
		},
		{
			name: "test config validation error with empty name",
			kind: "local",
			params: map[string]interface{}{
				"realm": "local",
			},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				"empty identity store name",
			),
		},
		{
			name:      "test config validation error with unsupported store kind",
			storeName: "default",
			kind:      "foobar",
			params: map[string]interface{}{
				"realm": "local",
			},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				"unsupported identity store type foobar",
			),
		},
		{
			name:      "test config validation error with empty store kind",
			storeName: "default",
			params: map[string]interface{}{
				"realm": "local",
			},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				"empty identity store type",
			),
		},
		{
			name:      "test config validation error with nil params",
			storeName: "default",
			kind:      "local",
			params:    map[string]interface{}{},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				"empty identity store parameters",
			),
		},
		{
			name:      "test config validation error with unsupported param field",
			storeName: "default",
			kind:      "local",
			params: map[string]interface{}{
				"path":  "foo",
				"realm": "local",
				"foo":   "bar",
			},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				fmt.Errorf("found unsupported %q field", "foo"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewIdentityStoreConfig(tc.storeName, tc.kind, tc.params)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}
			got := tests.Unpack(t, cfg)
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %v", tests.UnpackJSON(t, got))
				t.Errorf("NewIdentityStoreConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
