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

package authcrunch

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"path"
	"path/filepath"
	"testing"
)

func TestNewConfig(t *testing.T) {
	db, err := testutils.CreateTestDatabase("TestNewPortal")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	// t.Logf("%v", dbPath)

	var testcases = []struct {
		name string

		identityStores    []*ids.IdentityStoreConfig
		identityProviders []*idp.IdentityProviderConfig
		credentials       []credentials.Credential
		messaging         []messaging.Provider
		portals           []*authn.PortalConfig
		policies          []*authz.PolicyConfig

		shouldErr bool
		errPhase  string
		err       error
	}{
		{
			name:      "test empty config",
			shouldErr: true,
			errPhase:  "Validate",
			err:       fmt.Errorf("no portals and gatekeepers found"),
		},
		{
			name: "test failed local identity store config",
			identityStores: []*ids.IdentityStoreConfig{
				{
					Name: "localdb",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "local",
					},
				},
			},
			shouldErr: true,
			errPhase:  "AddIdentityStore",
			err: errors.ErrIdentityStoreConfigInvalid.WithArgs(
				fmt.Errorf("required field %q not found", "path"),
			),
		},
		{
			name: "test local identity stores having same realm but different paths",
			identityStores: []*ids.IdentityStoreConfig{
				{
					Name: "localdb1",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "local",
						"path":  filepath.Join(path.Dir(dbPath), "user_db1.json"),
					},
				},
				{
					Name: "localdb2",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "local",
						"path":  filepath.Join(path.Dir(dbPath), "user_db2.json"),
					},
				},
			},
			portals: []*authn.PortalConfig{
				{
					Name: "myportal",
					IdentityStores: []string{
						"localdb1",
						"localdb2",
					},
				},
			},
			shouldErr: true,
			errPhase:  "Validate",
			err:       fmt.Errorf("identity provider %q has the same %q realm as %q", "localdb2", "local", "localdb1"),
		},
		{
			name: "test local identity stores having different realms but the same path",
			identityStores: []*ids.IdentityStoreConfig{
				{
					Name: "localdb1",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "contoso",
						"path":  filepath.Join(path.Dir(dbPath), "user_db.json"),
					},
				},
			},
			identityProviders: []*idp.IdentityProviderConfig{
				{
					Name: "provider1",
					Kind: "oauth",
					Params: map[string]interface{}{
						"base_auth_url":         "https://localhost/oauth",
						"token_url":             "https://localhost/oauth/access_token",
						"authorization_url":     "https://localhost/oauth/authorize",
						"client_id":             "foo",
						"client_secret":         "bar",
						"driver":                "generic",
						"realm":                 "contoso",
						"required_token_fields": []interface{}{"access_token"},
						"response_type":         []interface{}{"code"},

						"tls_insecure_skip_verify":  true,
						"key_verification_disabled": true,
						"jwks_keys": map[string]string{
							"87329db33bf": "testdata/oauth/87329db33bf_pub.pem",
						},
					},
				},
			},
			portals: []*authn.PortalConfig{
				{
					Name: "myportal",
					IdentityStores: []string{
						"localdb1",
					},
					IdentityProviders: []string{
						"provider1",
					},
				},
			},
			shouldErr: true,
			errPhase:  "Validate",
			err:       fmt.Errorf("identity provider %q has the same %q realm as %q", "provider1", "contoso", "localdb1"),
		},
		{
			name: "test failed identity provider config",
			identityProviders: []*idp.IdentityProviderConfig{
				{
					Name: "authp",
					Kind: "oauth",
					Params: map[string]interface{}{
						"realm": "authp",
					},
				},
			},
			shouldErr: true,
			errPhase:  "AddIdentityProvider",
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				fmt.Errorf("required field %q not found", "driver"),
			),
		},
		{
			name: "test failed auth portal config",
			portals: []*authn.PortalConfig{
				{
					Name: "myportal",
				},
			},
			shouldErr: true,
			errPhase:  "Validate",
			err:       errors.ErrPortalConfigBackendsNotFound,
		},
		{
			name: "test failed credentials config",
			credentials: []credentials.Credential{
				&credentials.Generic{
					Name:     "foobar",
					Username: "foo",
				},
			},
			shouldErr: true,
			errPhase:  "AddCredential",
			err:       errors.ErrCredKeyValueEmpty.WithArgs("password"),
		},
		{
			name: "test failed messaging provider config",
			messaging: []messaging.Provider{
				&messaging.EmailProvider{
					Name:    "default",
					Address: "localhost",
					// Protocol:    "smtp",
					Credentials: "foobar",
					SenderEmail: "root@localhost",
				},
			},
			shouldErr: true,
			errPhase:  "AddMessagingProvider",
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("protocol"),
		},
		{
			name: "test failed authorization policy config",
			policies: []*authz.PolicyConfig{
				{
					Name: "mygatekeeper",
				},
			},
			shouldErr: true,
			errPhase:  "AddAuthorizationPolicy",
			err:       errors.ErrInvalidConfiguration.WithArgs("mygatekeeper", "access list rule config not found"),
		},
		{
			name: "test valid local auth config",
			credentials: []credentials.Credential{
				&credentials.Generic{
					Name:     "foobar",
					Username: "foo",
					Password: "bar",
				},
			},
			messaging: []messaging.Provider{
				&messaging.EmailProvider{
					Name:        "default",
					Address:     "localhost",
					Protocol:    "smtp",
					Credentials: "foobar",
					SenderEmail: "root@localhost",
				},
			},
			identityStores: []*ids.IdentityStoreConfig{
				{
					Name: "localdb",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "local",
						"path":  dbPath,
					},
				},
			},
			identityProviders: []*idp.IdentityProviderConfig{
				{
					Name: "contoso",
					Kind: "oauth",
					Params: map[string]interface{}{
						"base_auth_url":         "https://localhost/oauth",
						"token_url":             "https://localhost/oauth/access_token",
						"authorization_url":     "https://localhost/oauth/authorize",
						"client_id":             "foo",
						"client_secret":         "bar",
						"driver":                "generic",
						"realm":                 "contoso",
						"required_token_fields": []interface{}{"access_token"},
						"response_type":         []interface{}{"code"},

						"tls_insecure_skip_verify":  true,
						"key_verification_disabled": true,
						"jwks_keys": map[string]string{
							"87329db33bf": "testdata/oauth/87329db33bf_pub.pem",
						},
					},
				},
			},
			portals: []*authn.PortalConfig{
				{
					Name: "myportal",
					IdentityStores: []string{
						"localdb",
					},
				},
			},
			policies: []*authz.PolicyConfig{
				{
					Name: "mygatekeeper",
					AccessListRules: []*acl.RuleConfiguration{
						{
							Conditions: []string{
								"match roles authp/admin authp/user",
							},
							Action: "allow stop",
						},
					},
					AuthRedirectDisabled: true,
				},
			},
		},
		{
			name: "test valid config whan multiple portals have same realm from different identity stores",
			identityStores: []*ids.IdentityStoreConfig{
				{
					Name: "localdb1",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "local",
						"path":  filepath.Join(path.Dir(dbPath), "user_db1.json"),
					},
				},
				{
					Name: "localdb2",
					Kind: "local",
					Params: map[string]interface{}{
						"realm": "local",
						"path":  filepath.Join(path.Dir(dbPath), "user_db2.json"),
					},
				},
			},
			portals: []*authn.PortalConfig{
				{
					Name: "myportal1",
					IdentityStores: []string{
						"localdb1",
					},
				},
				{
					Name: "myportal2",
					IdentityStores: []string{
						"localdb2",
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}

			cfg := NewConfig()

			for _, item := range tc.credentials {
				err := cfg.AddCredential(item)
				if tests.EvalErrPhaseWithLog(t, err, "AddCredential", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			for _, item := range tc.messaging {
				err := cfg.AddMessagingProvider(item)
				if tests.EvalErrPhaseWithLog(t, err, "AddMessagingProvider", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			for _, item := range tc.identityStores {
				err := cfg.AddIdentityStore(item.Name, item.Kind, item.Params)
				if tests.EvalErrPhaseWithLog(t, err, "AddIdentityStore", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			for _, item := range tc.identityProviders {
				err := cfg.AddIdentityProvider(item.Name, item.Kind, item.Params)
				if tests.EvalErrPhaseWithLog(t, err, "AddIdentityProvider", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			for _, item := range tc.portals {
				err := cfg.AddAuthenticationPortal(item)
				if tests.EvalErrPhaseWithLog(t, err, "AddAuthenticationPortal", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			for _, item := range tc.policies {
				err := cfg.AddAuthorizationPolicy(item)
				if tests.EvalErrPhaseWithLog(t, err, "AddAuthorizationPolicy", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			err := cfg.Validate()
			if err != nil {
				if tests.EvalErrPhaseWithLog(t, err, "Validate", tc.errPhase, tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}
		})
	}
}

func TestValidateNilConfig(t *testing.T) {
	var cfg *Config
	err := cfg.Validate()
	tests.EvalErrWithLog(t, err, "Validate", true, fmt.Errorf("config is nil"), nil)
}
