// Copyright 2020 Paul Greenberg greenpau@outlook.com
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
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/aaasf/internal/tests"
	"github.com/greenpau/aaasf/internal/testutils"
	"github.com/greenpau/aaasf/pkg/acl"
	"github.com/greenpau/aaasf/pkg/authn/backends"
	"github.com/greenpau/aaasf/pkg/authn/cookie"
	"github.com/greenpau/aaasf/pkg/authn/registration"
	"github.com/greenpau/aaasf/pkg/authn/transformer"
	"github.com/greenpau/aaasf/pkg/authn/ui"
	"github.com/greenpau/aaasf/pkg/authz/options"
	"github.com/greenpau/aaasf/pkg/errors"
	logutil "github.com/greenpau/aaasf/pkg/util/log"
	"go.uber.org/zap"
	"testing"
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
		userRegistrationConfig *registration.Config
		userTransformerConfigs []*transformer.Config
		cookieConfig           *cookie.Config
		backendConfigsFunc     func() []backends.Config
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
			backendConfigsFunc: func() []backends.Config {
				return nil
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
			backendConfigsFunc: func() []backends.Config {
				return nil
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
				}
			},
			backendConfigsFunc: func() []backends.Config {
				m := map[string]interface{}{
					"name":   "local_backend",
					"method": "local",
					"realm":  "local",
					"path":   dbPath,
				}
				backendConfig, err := backends.NewConfig(m)
				if err != nil {
					return []backends.Config{}
				}
				return []backends.Config{*backendConfig}
			},
			want: `{
              "config": {
			    "name": "myportal",
				"ui": {
				  "theme": "basic"
				},
				"token_validator_options": {
				  "validate_bearer_header": true
				},
				"access_list_configs": [
                  {
                    "action": "` + defaultPortalACLAction + `",
                    "conditions": ["` + defaultPortalACLCondition + `"]
				  }
				],
                "backend_configs": [
                  {
                    "local": {
                      "method": "local",
                      "name": "local_backend",
                      "path": "` + dbPath + `",
                      "realm": "local"
                    }
                  }
                ]
              }
            }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			logger := tc.loggerFunc()
			cfg := tc.configFunc()
			if cfg != nil {
				if tc.uiConfig != nil {
					cfg.UI = tc.uiConfig
				}
				if tc.userRegistrationConfig != nil {
					cfg.UserRegistrationConfig = tc.userRegistrationConfig
				}
				if len(tc.userTransformerConfigs) > 0 {
					cfg.UserTransformerConfigs = tc.userTransformerConfigs
				}
				if tc.cookieConfig != nil {
					cfg.CookieConfig = tc.cookieConfig
				}
				backendConfigs := tc.backendConfigsFunc()
				if len(backendConfigs) > 0 {
					cfg.BackendConfigs = backendConfigs
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

			portal, err := NewPortal(cfg, logger)
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

			// t.Logf("JSON: %s", tests.UnpackJSON(t, got))
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("NewPortal() config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
