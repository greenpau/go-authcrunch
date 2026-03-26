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

package authproxy

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestParseConfig(t *testing.T) {
	var testcases = []struct {
		name      string
		config    []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "basic and api key auth with realms",
			config: []string{
				"basic auth portal default realm foo",
				"api key auth portal default realm bar",
			},
			want: map[string]interface{}{
				"realms": map[string]any{
					"foo": map[string]any{
						"basic_auth_enabled": true,
						"portal_name":        "default",
					},
					"bar": map[string]any{
						"api_key_auth_enabled": true,
						"portal_name":          "default",
					},
				},
			},
		},
		{
			name: "basic and api key auth with foo realm in bar portal",
			config: []string{
				"basic auth realm foo portal bar",
				"api key auth realm foo portal bar",
			},
			want: map[string]interface{}{
				"realms": map[string]any{
					"foo": map[string]any{
						"api_key_auth_enabled": true,
						"basic_auth_enabled":   true,
						"portal_name":          "bar",
					},
				},
			},
		},
		{
			name: "basic and api key auth with foo realm in remote portal",
			config: []string{
				"basic auth realm foo portal https://localhost:10002/auth",
				"api key auth realm foo portal https://localhost:10002/auth",
			},
			want: map[string]interface{}{
				"realms": map[string]any{
					"foo": map[string]any{
						"api_key_auth_enabled": true,
						"basic_auth_enabled":   true,
						"is_remote":            true,
						"remote_addr":          "https://localhost:10002/auth",
					},
				},
			},
		},
		{
			name: "same realm attached to two different remote portal",
			config: []string{
				"basic auth realm foo portal https://localhost:10003/auth",
				"api key auth realm foo portal https://localhost:30001/auth",
			},

			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("api key auth realm foo portal https://localhost:30001/auth"),
		},
		{
			name: "insecure remote portal",
			config: []string{
				"api key auth realm foo portal http://localhost:30001/auth",
			},

			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("api key auth realm foo portal http://localhost:30001/auth"),
		},
		{
			name: "invalid config",
			config: []string{
				"foo",
			},
			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("foo"),
		},
		{
			name:      "empty config",
			config:    []string{},
			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("empty config"),
		},
		{
			name:      "malformed config with incomplete realm",
			config:    []string{"basic auth realm"},
			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("basic auth realm"),
		},
		{
			name:      "malformed config with unsupported keyword",
			config:    []string{"basic auth realm foo bar baz"},
			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("basic auth realm foo bar baz"),
		},
		{
			name:      "malformed config with bad encoding",
			config:    []string{`basic auth realm foo bar "baz`},
			shouldErr: true,
			err:       fmt.Errorf(`parse error on line 1, column 30: extraneous or missing " in quoted-field`),
		},
		{
			name: "portal id is not in config",
			config: []string{
				"basic auth realm foo",
			},
			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("basic auth realm foo"),
		},
		{
			name: "realm name is not in config",
			config: []string{
				"basic auth portal foo",
			},
			shouldErr: true,
			err:       errors.ErrAuthProxyConfigInvalid.WithArgs("basic auth portal foo"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %v", tc.config))
			config, err := ParseConfig(tc.config)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			// got := make(map[string]interface{})
			got, err := tests.UnpackDict(config)
			// got["config"] = tests.UnpackDict(config)
			if tests.EvalErrWithLog(t, err, nil, false, nil, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}

func TestConfigMethods(t *testing.T) {
	type mockAuthenticator struct{ Authenticator }
	auth := &mockAuthenticator{}

	rawConfig := []string{
		"basic auth realm foo portal bar",
		"api key auth realm baz portal bar",
		"basic auth realm remote portal https://localhost:10002/auth",
	}

	cfg, err := ParseConfig(rawConfig)
	if err != nil {
		t.Fatalf("failed to parse base config: %v", err)
	}

	t.Run("test has realm", func(t *testing.T) {
		tests := []struct {
			name  string
			realm string
			want  bool
		}{
			{"existing realm", "foo", true},
			{"existing remote realm", "remote", true},
			{"non-existent realm", "nonexistent", false},
			{"empty realm", "", false},
		}
		for _, tc := range tests {
			if got := cfg.HasRealm(tc.realm); got != tc.want {
				t.Errorf("%s: HasRealm(%q) = %v, want %v", tc.name, tc.realm, got, tc.want)
			}
		}
	})

	t.Run("test has portal", func(t *testing.T) {
		tests := []struct {
			name   string
			portal string
			want   bool
		}{
			{"existing local portal", "bar", true},
			{"non-existent portal", "missing", false},
			{"empty portal string", "", false},
		}
		for _, tc := range tests {
			if got := cfg.HasPortal(tc.portal); got != tc.want {
				t.Errorf("%s: HasPortal(%q) = %v, want %v", tc.name, tc.portal, got, tc.want)
			}
		}
	})

	t.Run("test authenticator workflow", func(t *testing.T) {
		if err := cfg.AddAuthenticator("bar", auth); err != nil {
			t.Errorf("AddAuthenticator failed: %v", err)
		}

		gotAuth, err := cfg.GetAuthenticator("foo")
		if err != nil || gotAuth != auth {
			t.Errorf("GetAuthenticator(foo) failed: got %v, err %v", gotAuth, err)
		}

		gotAuthBaz, err := cfg.GetAuthenticator("baz")
		if err != nil || gotAuthBaz != auth {
			t.Errorf("GetAuthenticator(baz) failed: got %v, err %v", gotAuthBaz, err)
		}

		if err := cfg.AddAuthenticator("nonexistent", auth); err == nil {
			t.Error("AddAuthenticator should have failed with missing portal")
		}

		if err := cfg.AddAuthenticator("", auth); err == nil {
			t.Error("AddAuthenticator should have failed with empty portal name")
		}

		if _, err := cfg.GetAuthenticator("ghost"); err == nil {
			t.Error("GetAuthenticator should have failed with missing realm")
		}
	})

	t.Run("test has auth kind", func(t *testing.T) {
		tests := []struct {
			realm    string
			hasBasic bool
			hasAPI   bool
		}{
			{"foo", true, false},
			{"baz", false, true},
			{"remote", true, false},
			{"missing", false, false},
		}
		for _, tc := range tests {
			if got := cfg.HasBasicAuth(tc.realm); got != tc.hasBasic {
				t.Errorf("realm %s: HasBasicAuth = %v, want %v", tc.realm, got, tc.hasBasic)
			}
			if got := cfg.HasAPIKeyAuth(tc.realm); got != tc.hasAPI {
				t.Errorf("realm %s: HasAPIKeyAuth = %v, want %v", tc.realm, got, tc.hasAPI)
			}
		}
	})
}
