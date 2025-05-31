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

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"

	// "github.com/greenpau/go-authcrunch/pkg/authn/registration"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/credentials"

	// "github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func TestNewServer(t *testing.T) {
	db, err := testutils.CreateTestDatabase("TestNewPortal")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	// t.Logf("%v", dbPath)

	var testcases = []struct {
		name   string
		logger *zap.Logger

		identityStores    []*ids.IdentityStoreConfig
		identityProviders []*idp.IdentityProviderConfig
		credentials       []credentials.Credential
		messaging         []messaging.Provider
		portals           []*authn.PortalConfig
		policies          []*authz.PolicyConfig

		want string

		shouldErr bool
		err       error
	}{
		{
			name:      "test server without portals and gatekeepers",
			logger:    logutil.NewLogger(),
			shouldErr: true,
			err:       fmt.Errorf("no portals and gatekeepers found"),
		},
		{
			name:   "test server with valid local auth config",
			logger: logutil.NewLogger(),
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
			want: `{
              "config": {
                "authentication_portals": [
                  {
                    "access_list_configs": [
						{
							"action": "allow stop",
							"comment": "admin role name match",
							"conditions": ["match role authp/admin"]
						},
						{
							"action": "allow stop",
							"comment": "user role name match",
							"conditions": ["match role authp/user"]
						},
						{
							"action": "allow stop",
							"comment": "guest role name match",
							"conditions": ["match role authp/guest"]
						}
                    ],
                    "identity_stores": [
                      "localdb"
                    ],
                    "name": "myportal",
					"portal_admin_roles": {
						"authp/admin": true
					},
					"portal_user_roles": {
						"authp/user": true
					},
					"portal_guest_roles": {
						"authp/guest": true
					},
                    "token_validator_options": {
                      "validate_bearer_header": true
                    },
                    "ui": {
                      "theme": "basic"
                    }
                  }
                ],
                "authorization_policies": [
                  {
                    "access_list_rules": [
                      {
                        "action": "allow stop",
                        "conditions": [
                          "match roles authp/admin authp/user"
                        ]
                      }
                    ],
                    "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
                    "auth_url_path": "/auth",
                    "disable_auth_redirect": true,
                    "name": "mygatekeeper"
                  }
                ],
                "credentials": {
                  "generic": [
                    {
                      "name": "foobar",
                      "password": "bar",
                      "username": "foo"
                    }
                  ]
                },
                "identity_providers": [
                  {
                    "kind": "oauth",
                    "name": "contoso",
                    "params": {
                      "authorization_url": "https://localhost/oauth/authorize",
                      "base_auth_url": "https://localhost/oauth",
                      "client_id": "foo",
                      "client_secret": "bar",
                      "driver": "generic",
                      "jwks_keys": {
                        "87329db33bf": "testdata/oauth/87329db33bf_pub.pem"
                      },
                      "key_verification_disabled": true,
                      "realm": "contoso",
                      "required_token_fields": [
                        "access_token"
                      ],
                      "response_type": [
                        "code"
                      ],
                      "tls_insecure_skip_verify": true,
                      "token_url": "https://localhost/oauth/access_token"
                    }
                  }
                ],
                "identity_stores": [
                  {
                    "kind": "local",
                    "name": "localdb",
                    "params": {
                      "path": "` + dbPath + `",
                      "realm": "local"
                    }
                  }
                ],
                "messaging": {
                  "email_providers": [
                    {
                      "address": "localhost",
                      "credentials": "foobar",
                      "name": "default",
                      "protocol": "smtp",
                      "sender_email": "root@localhost"
                    }
                  ]
                }
              }
		    }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			cfg := NewConfig()

			for _, item := range tc.credentials {
				if err := cfg.AddCredential(item); err != nil {
					t.Fatal(err)
				}
			}

			for _, item := range tc.messaging {
				if err := cfg.AddMessagingProvider(item); err != nil {
					t.Fatal(err)
				}
			}

			for _, item := range tc.identityStores {
				if err := cfg.AddIdentityStore(item.Name, item.Kind, item.Params); err != nil {
					t.Fatal(err)
				}
			}

			for _, item := range tc.identityProviders {
				if err := cfg.AddIdentityProvider(item.Name, item.Kind, item.Params); err != nil {
					t.Fatal(err)
				}
			}

			for _, item := range tc.portals {
				if err := cfg.AddAuthenticationPortal(item); err != nil {
					t.Fatal(err)
				}
			}

			for _, item := range tc.policies {
				if err := cfg.AddAuthorizationPolicy(item); err != nil {
					t.Fatal(err)
				}
			}

			server, err := NewServer(cfg, tc.logger)
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

			got := make(map[string]interface{})
			got["config"] = server.GetConfig()
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %s", tests.UnpackJSON(t, got))
				t.Errorf("NewServer() config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
