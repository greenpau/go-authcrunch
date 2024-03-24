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

package authn

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func TestNewPortal(t *testing.T) {
	db, err := testutils.CreateTestDatabase("TestNewPortal")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	t.Logf("%v", dbPath)

	var testcases = []struct {
		name      string
		disabled  bool
		want      string
		shouldErr bool
		err       error

		loggerFunc func() *zap.Logger
		configFunc func() *PortalConfig

		// Portal Config fields.
		uiConfig               *ui.Parameters
		userTransformerConfigs []*transformer.Config
		cookieConfig           *cookie.Config
		identityStoreConfigs   []*ids.IdentityStoreConfig
		aclConfigs             []*acl.RuleConfiguration
		tokenValidatorOptions  *options.TokenValidatorOptions
		tokenGrantorOptions    *options.TokenGrantorOptions
		cryptoRawConfigs       []string
	}{
		{
			name: "test new portal without logger",
			loggerFunc: func() *zap.Logger {
				return nil
			},
			configFunc: func() *PortalConfig {
				return nil
			},
			shouldErr: true,
			err:       errors.ErrNewPortalLoggerNil,
		},
		{
			name: "test new portal without config",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PortalConfig {
				return nil
			},
			shouldErr: true,
			err:       errors.ErrNewPortalConfigNil,
		},
		{
			name: "test new portal without name",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PortalConfig {
				return &PortalConfig{}
			},
			shouldErr: true,
			err:       errors.ErrNewPortal.WithArgs(errors.ErrPortalConfigNameNotFound),
		},
		{
			name: "test new portal without backends",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PortalConfig {
				return &PortalConfig{
					Name: "myportal",
				}
			},
			shouldErr: true,
			err:       errors.ErrNewPortal.WithArgs(errors.ErrPortalConfigBackendsNotFound),
		},
		{
			name: "test new portal backed by local database",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PortalConfig {
				return &PortalConfig{
					Name: "myportal",
					IdentityStores: []string{
						"local_backend",
					},
				}
			},
			identityStoreConfigs: []*ids.IdentityStoreConfig{
				{
					Name: "local_backend",
					Kind: "local",
					Params: map[string]interface{}{
						"path":  dbPath,
						"realm": "local",
					},
				},
			},
			want: `{
              "config": {
			    "name": "myportal",
				"ui": {
				  "theme": "basic"
				},
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
				"identity_stores": ["local_backend"]
              }
            }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			cfg := tc.configFunc()
			if cfg != nil {
				if tc.uiConfig != nil {
					cfg.UI = tc.uiConfig
				}
				if len(tc.userTransformerConfigs) > 0 {
					cfg.UserTransformerConfigs = tc.userTransformerConfigs
				}
				if tc.cookieConfig != nil {
					cfg.CookieConfig = tc.cookieConfig
				}
				if len(tc.aclConfigs) > 0 {
					cfg.AccessListConfigs = tc.aclConfigs
				}
				if tc.tokenValidatorOptions != nil {
					cfg.TokenValidatorOptions = tc.tokenValidatorOptions
				}
				if tc.tokenGrantorOptions != nil {
					cfg.TokenGrantorOptions = tc.tokenGrantorOptions
				}
				for _, s := range tc.cryptoRawConfigs {
					cfg.AddRawCryptoConfigs(s)
				}
			}

			params := PortalParameters{
				Config: cfg,
				Logger: tc.loggerFunc(),
			}

			for _, storeCfg := range tc.identityStoreConfigs {
				store, err := ids.NewIdentityStore(storeCfg, logutil.NewLogger())
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Configure(); err != nil {
					t.Fatal(err)
				}
				params.IdentityStores = append(params.IdentityStores, store)
			}

			portal, err := NewPortal(params)
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
			got["config"] = tests.Unpack(t, portal.config)
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %s", tests.UnpackJSON(t, got))
				t.Errorf("NewPortal() config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
