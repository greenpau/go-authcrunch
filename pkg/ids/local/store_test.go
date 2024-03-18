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

package local

import (
	"fmt"
	"path"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func TestNewIdentityStore(t *testing.T) {
	db, err := testutils.CreateTestDatabase("TestLocalIdentityStore")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	testcases := []struct {
		name              string
		config            *Config
		logger            *zap.Logger
		testRequests      bool
		publicKeysEnabled bool
		want              map[string]interface{}
		shouldErr         bool
		err               error
	}{
		{
			name: "test local store",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
				Path:  dbPath,
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"name":  "local_store",
				"kind":  "local",
				"realm": "local",
				"config": map[string]interface{}{
					"name":  "local_store",
					"realm": "local",
					"path":  dbPath,
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("las la-key la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
			},
		},
		{
			name: "test local store with operations",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
				Path:  dbPath,
			},
			logger:            logutil.NewLogger(),
			testRequests:      true,
			publicKeysEnabled: true,
			want: map[string]interface{}{
				"name":  "local_store",
				"realm": "local",
				"kind":  "local",
				"config": map[string]interface{}{
					"name":  "local_store",
					"realm": "local",
					"path":  dbPath,
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("las la-key la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
				"ops": map[string]bool{
					"AddAPIKey":       true,
					"AddKeyGPG":       true,
					"AddKeySSH":       true,
					"AddMfaToken":     true,
					"AddUser":         true,
					"ChangePassword":  true,
					"DeleteAPIKey":    true,
					"DeleteMfaToken":  true,
					"DeletePublicKey": true,
					"DeleteUser":      true,
					"GetAPIKeys":      false,
					"GetMfaTokens":    false,
					"GetMfaToken":     true,
					"GetPublicKeys":   false,
					"GetUser":         false,
					"GetUsers":        false,
					"IdentifyUser":    false,
					"LookupAPIKey":    true,
				},
			},
		},
		{
			name: "test empty config name",
			config: &Config{
				Name:  "",
				Realm: "local",
				Path:  filepath.Join(path.Dir(dbPath), "user_db1.json"),
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			err:       errors.ErrIdentityStoreConfigureNameEmpty,
		},
		{
			name: "test empty config realm",
			config: &Config{
				Name: "local_store",
				Path: filepath.Join(path.Dir(dbPath), "user_db1.json"),
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			err:       errors.ErrIdentityStoreConfigureRealmEmpty,
		},
		{
			name: "test empty config database path",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			err:       errors.ErrIdentityStoreLocalConfigurePathEmpty,
		},
		{
			name: "test empty logger",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
				Path:  filepath.Join(path.Dir(dbPath), "user_db1.json"),
			},
			shouldErr: true,
			err:       errors.ErrIdentityStoreConfigureLoggerNotFound,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("db path: %v", tc.config.Path))
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			st, err := NewIdentityStore(tc.config, tc.logger)
			if tests.EvalErrWithLog(t, err, "NewIdentityStore", tc.shouldErr, tc.err, msgs) {
				return
			}

			if tc.testRequests {
				results := make(map[string]bool)
				if err := st.Configure(); err != nil {
					t.Fatalf("configuration error: %v", err)
				}

				ops := []operator.Type{
					operator.ChangePassword,
					operator.AddKeySSH,
					operator.AddKeyGPG,
					operator.GetPublicKeys,
					operator.DeletePublicKey,
					operator.AddMfaToken,
					operator.GetMfaTokens,
					operator.GetMfaToken,
					operator.DeleteMfaToken,
					operator.AddUser,
					operator.GetUser,
					operator.GetUsers,
					operator.DeleteUser,
					operator.IdentifyUser,
					operator.AddAPIKey,
					operator.DeleteAPIKey,
					operator.GetAPIKeys,
					operator.LookupAPIKey,
				}

				if tc.publicKeysEnabled {
					ops = append(ops, operator.GetPublicKeys)
				}

				for _, op := range ops {
					req := &requests.Request{
						User: requests.User{
							Username: tests.TestUser1,
							Email:    tests.TestEmail1,
						},
					}
					if op == operator.GetPublicKeys {
						req.Key = requests.Key{
							Usage: "ssh",
						}
					}

					if err := st.Request(op, req); err != nil {
						results[op.String()] = true
					} else {
						results[op.String()] = false
					}
				}

				got["ops"] = results
			}

			got["name"] = st.GetName()
			got["realm"] = st.GetRealm()
			got["config"] = st.GetConfig()
			got["kind"] = st.GetKind()

			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}

func TestConfigureIdentityStore(t *testing.T) {
	db, err := testutils.CreateTestDatabase("TestLocalIdentityStore")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	testcases := []struct {
		name           string
		configs        []*Config
		testRequests   bool
		skipPublicKeys bool
		want           map[string]interface{}
		shouldErr      bool
		err            error
	}{
		{
			name: "test two configs having same realm and same path",
			configs: []*Config{
				&Config{
					Name:  "local_store",
					Realm: "local",
					Path:  dbPath,
				},
				&Config{
					Name:  "local_store",
					Realm: "local",
					Path:  dbPath,
				},
			},
			want: map[string]interface{}{
				"local_store_kind":  "local",
				"local_store_realm": "local",
				"local_store_config": map[string]interface{}{
					"name":  "local_store",
					"realm": "local",
					"path":  dbPath,
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("las la-key la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
				"local_store_configured": true,
			},
		},
		{
			name: "test unsupported file path",
			configs: []*Config{
				&Config{
					Name:  "local_store",
					Realm: "local",
					Path:  "/dev/null",
				},
			},
			shouldErr: true,
			err:       errors.ErrNewDatabase.WithArgs("/dev/null", "null path"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			logger := logutil.NewLogger()

			for i, config := range tc.configs {
				msgs = append(msgs, fmt.Sprintf("db path %d: %v", i, config.Path))
				msgs = append(msgs, fmt.Sprintf("config:\n%v", config))
				b, err := NewIdentityStore(config, logger)
				if err != nil {
					t.Fatalf("failed creating identity store: %v", err)
				}

				err = b.Configure()
				if i == 0 && len(tc.configs) > 1 {
					if err != nil {
						t.Fatalf("first config expected to succeed, got error: %v", err)
					}
				} else {
					if tests.EvalErrWithLog(t, err, "Configure", tc.shouldErr, tc.err, msgs) {
						return
					}
				}

				got[b.GetName()+"_realm"] = b.GetRealm()
				got[b.GetName()+"_kind"] = b.GetKind()
				got[b.GetName()+"_config"] = b.GetConfig()
				got[b.GetName()+"_configured"] = b.Configured()
			}
			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}
