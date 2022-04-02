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

package authz

import (
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"testing"
)

func TestNewGatekeeper(t *testing.T) {

	var testcases = []struct {
		name      string
		disabled  bool
		want      string
		shouldErr bool
		err       error

		loggerFunc func() *zap.Logger
		configFunc func() *PolicyConfig

		bypassConfigs      []*bypass.Config
		injectorConfigs    []*injector.Config
		aclConfigs         []*acl.RuleConfiguration
		cryptoRawConfigs   []string
		authProxyRawConfig []string
	}{
		{
			name: "test new gatekeeper without logger",
			loggerFunc: func() *zap.Logger {
				return nil
			},
			configFunc: func() *PolicyConfig {
				return nil
			},
			shouldErr: true,
			err:       errors.ErrNewGatekeeperLoggerNil,
		},
		{
			name: "test new gatekeeper without config",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PolicyConfig {
				return nil
			},
			shouldErr: true,
			err:       errors.ErrNewGatekeeperConfigNil,
		},
		{
			name: "test new gatekeeper without name",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PolicyConfig {
				return &PolicyConfig{}
			},
			shouldErr: true,
			err:       errors.ErrNewGatekeeper.WithArgs(errors.ErrPolicyConfigNameNotFound),
		},
		{
			name: "test new gatekeeper",
			loggerFunc: func() *zap.Logger {
				return logutil.NewLogger()
			},
			configFunc: func() *PolicyConfig {
				return &PolicyConfig{
					Name:        "mygatekeeper",
					AuthURLPath: "/auth",
				}
			},
			aclConfigs: []*acl.RuleConfiguration{
				{
					Conditions: []string{"match roles anonymous guest admin"},
					Action:     "allow stop",
				},
				{
					Conditions: []string{"match roles superadmin"},
					Action:     "allow stop",
				},
				{
					Conditions: []string{"match roles admin editor viewer"},
					Action:     "allow stop",
				},
				{
					Conditions: []string{"match roles AzureAD_Administrator AzureAD_Editor AzureAD_Viewer"},
					Action:     "allow stop",
				},
				{
					Conditions: []string{"match roles everyone Everyone"},
					Action:     "allow stop",
				},
			},
			cryptoRawConfigs: []string{
				"key verify 0e2fdcf8-6868-41a7-884b-7308795fc286",
			},
			want: `{
              "config": {
                "name": "mygatekeeper",
                "access_list_rules": [
                  {
                    "action": "allow stop",
                    "conditions": ["match roles anonymous guest admin"]
                  },
                  {
                    "action": "allow stop",
                    "conditions": ["match roles superadmin"]
                  },
                  {
                    "action": "allow stop",
                    "conditions": ["match roles admin editor viewer"]
                  },
                  {
                    "action": "allow stop",
                    "conditions": ["match roles AzureAD_Administrator AzureAD_Editor AzureAD_Viewer"]
                  },
                  {
                    "action": "allow stop",
                    "conditions": ["match roles everyone Everyone"]
                  }
                ],
                "auth_redirect_query_param": "redirect_url",
                "auth_redirect_status_code": 302,
                "auth_url_path": "/auth",
                "crypto_key_configs": [
                  {
                    "algorithm": "hmac",
                    "id": "0",
                    "source": "config",
                    "token_lifetime": 900,
                    "token_name": "access_token",
                    "token_secret": "0e2fdcf8-6868-41a7-884b-7308795fc286",
                    "usage": "verify"
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
				cfg.BypassConfigs = tc.bypassConfigs
				cfg.HeaderInjectionConfigs = tc.injectorConfigs
				cfg.AccessListRules = tc.aclConfigs
				cfg.cryptoRawConfigs = tc.cryptoRawConfigs
				cfg.authProxyRawConfig = tc.authProxyRawConfig
			}

			gatekeeper, err := NewGatekeeper(cfg, logger)
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
			got["config"] = tests.Unpack(t, gatekeeper.config)
			want := tests.Unpack(t, tc.want)

			// t.Logf("JSON: %s", tests.UnpackJSON(t, got))
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("NewGatekeeper() config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
