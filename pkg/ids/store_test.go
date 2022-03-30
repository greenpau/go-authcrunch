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
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"testing"
)

func TestNewIdentityStore(t *testing.T) {
	testcases := []struct {
		name          string
		config        *IdentityStoreConfig
		disableLogger bool
		want          string
		shouldErr     bool
		err           error
	}{
		{
			name: "test local identity store",
			config: &IdentityStoreConfig{
				Name: "default",
				Kind: "local",
				Params: map[string]interface{}{
					"path":  "foo",
					"realm": "local",
				},
			},
			want: `{
			  "name": "default",
			  "kind": "local",
			  "realm": "local"
            }`,
		},
		{
			name: "test ldap identity store",
			config: &IdentityStoreConfig{
				Name: "contoso.com",
				Kind: "ldap",
				Params: map[string]interface{}{
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
			},
			want: `{
              "name": "contoso.com",
              "kind": "ldap",
			  "realm": "contoso.com"
			}`,
		},
		{
			name: "test logger nil error",
			config: &IdentityStoreConfig{
				Name: "default",
				Kind: "local",
				Params: map[string]interface{}{
					"path":  "foo",
					"realm": "local",
				},
			},
			disableLogger: true,
			shouldErr:     true,
			err:           errors.ErrIdentityStoreConfigureLoggerNotFound,
		},
		{
			name: "test config validation error",
			config: &IdentityStoreConfig{
				Kind: "local",
				Params: map[string]interface{}{
					"path":  "foo",
					"realm": "local",
				},
			},
			shouldErr: true,
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				"empty identity store name",
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var logger *zap.Logger
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))
			if !tc.disableLogger {
				logger = logutil.NewLogger()
			}

			st, err := NewIdentityStore(tc.config, logger)
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
			got := map[string]interface{}{
				"name":  st.GetName(),
				"realm": st.GetRealm(),
				"kind":  st.GetKind(),
			}

			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %v", tests.UnpackJSON(t, got))
				t.Errorf("NewIdentityStore() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
