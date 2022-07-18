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

package sso

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestNewSingleSignOnProviderConfig(t *testing.T) {
	testcases := []struct {
		name      string
		input     map[string]interface{}
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test aws sso provider",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "aws",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			want: `{
				"name":             "aws",
                "driver":           "aws",
                "entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
                "cert_path":        "../../testdata/sso/authp_saml.crt",
                "locations": [
                    "https://localhost/sso/aws",
                    "https://127.0.0.1/sso/aws"
                ]
            }`,
		},
		{
			name:      "test empty sso provider parameters",
			input:     nil,
			shouldErr: true,
			err: errors.ErrSingleSignOnProviderConfigInvalid.WithArgs(
				"input data error",
				fmt.Errorf("empty identity provider parameters"),
			),
		},
		{
			name: "test json Unmarshal error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           []string{"aws"},
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err: errors.ErrSingleSignOnProviderConfigInvalid.WithArgs(
				"json.Unmarshal error",
				fmt.Errorf("json: cannot unmarshal array into Go struct field SingleSignOnProviderConfig.driver of type string"),
			),
		},
		{
			name: "test config validation error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "foo",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "unsupported driver name"),
		},
		{
			name: "test empty provider name error",
			input: map[string]interface{}{
				"name":             "",
				"driver":           "aws",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty provider name"),
		},
		{
			name: "test empty entity id error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "aws",
				"entity_id":        "",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty entity id"),
		},
		{
			name: "test empty private key path error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "aws",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty private key path"),
		},
		{
			name: "test empty cert path error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "aws",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty cert path"),
		},
		{
			name: "test empty locations error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "aws",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations":        []string{},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty locations"),
		},
		{
			name: "test empty driver name error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty driver name"),
		},
		{
			name: "test required field not found error",
			input: map[string]interface{}{
				"name":   "aws",
				"driver": "aws",
				// "entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			shouldErr: true,
			err: errors.ErrSingleSignOnProviderConfigInvalid.WithArgs(
				"input data error",
				fmt.Errorf("required field %q not found", "entity_id"),
			),
		},
		{
			name: "test unsupported field found error",
			input: map[string]interface{}{
				"name":             "aws",
				"driver":           "aws",
				"entity_id":        "caddy-authp-idp",
				"private_key_path": "../../testdata/sso/authp_saml.key",
				"cert_path":        "../../testdata/sso/authp_saml.crt",
				"locations": []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
				"foo": "bar",
			},
			shouldErr: true,
			err: errors.ErrSingleSignOnProviderConfigInvalid.WithArgs(
				"input data error",
				fmt.Errorf("found unsupported %q field", "foo"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewSingleSignOnProviderConfig(tc.input)
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
				t.Errorf("NewSingleSignOnProviderConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
