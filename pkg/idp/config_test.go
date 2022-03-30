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

package idp

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestNewIdentityProviderConfig(t *testing.T) {
	testcases := []struct {
		name      string
		driver    string
		kind      string
		params    map[string]interface{}
		want      string
		shouldErr bool
		err       error
	}{
		{
			name:   "test google identity provider",
			driver: "google",
			kind:   "oauth",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				"driver":        "google",
				"realm":         "localdb",
				"scopes":        []string{"openid", "email", "profile"},
			},
			want: `{
              "name": "google",
              "kind": "oauth",
              "params": {
                "client_id": "foo.apps.googleusercontent.com",
                "client_secret": "foobar",
                "driver": "google",
                "realm": "localdb",
                "scopes": ["openid", "email", "profile"]
              }
            }`,
		},
		{
			name:   "test jumpcloud identity provider",
			driver: "jumpcloud",
			kind:   "saml",
			params: map[string]interface{}{
				"driver":                 "generic",
				"realm":                  "jumpcloud",
				"idp_metadata_location":  "JumpCloud-saml2-metadata.xml",
				"idp_sign_cert_location": "certificate.pem",
				"idp_login_url":          "https://sso.jumpcloud.com/saml2/authp",
				"application_name":       "Auth Portal",
				"entity_id":              "urn:authp",
				"acs_urls":               []string{"https://localhost/saml/jumpcloud"},
			},
			want: `{
              "kind": "saml",
              "name": "jumpcloud",
              "params": {
                "acs_urls": [
                  "https://localhost/saml/jumpcloud"
                ],
                "application_name": "Auth Portal",
                "entity_id": "urn:authp",
                "idp_login_url": "https://sso.jumpcloud.com/saml2/authp",
                "idp_metadata_location": "JumpCloud-saml2-metadata.xml",
                "idp_sign_cert_location": "certificate.pem",
                "driver": "generic",
                "realm": "jumpcloud"
              }
            }`,
		},
		{
			name: "test config validation error",
			// driver: "google",
			kind: "oauth",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				"driver":        "google",
				"realm":         "localdb",
				"scopes":        []string{"openid", "email", "profile"},
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigInvalid.WithArgs("empty identity provider name"),
		},
		{
			name:   "test config validation error with unsupported provider kind",
			driver: "google",
			kind:   "foobar",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				"driver":        "google",
				"realm":         "localdb",
				"scopes":        []string{"openid", "email", "profile"},
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				"unsupported identity provider type foobar",
			),
		},
		{
			name:   "test config validation error with empty provider kind",
			driver: "google",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				"driver":        "google",
				"realm":         "localdb",
				"scopes":        []string{"openid", "email", "profile"},
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				"empty identity provider type",
			),
		},
		{
			name:      "test config validation error with nil params",
			driver:    "google",
			kind:      "oauth",
			params:    map[string]interface{}{},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				"empty identity provider parameters",
			),
		},
		{
			name:   "test config validation error with unsupported param field",
			driver: "google",
			kind:   "oauth",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				"driver":        "google",
				"realm":         "localdb",
				"scopes":        []string{"openid", "email", "profile"},
				"foo":           "bar",
			},

			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				fmt.Errorf("found unsupported %q field", "foo"),
			),
		},
		{
			name:   "test config validation error with required field not found",
			driver: "google",
			kind:   "oauth",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				// "driver":      "google",
				"realm":  "localdb",
				"scopes": []string{"openid", "email", "profile"},
			},

			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				fmt.Errorf("required field %q not found", "driver"),
			),
		},
		{
			name:   "test oauth config validation error",
			driver: "google",
			kind:   "oauth",
			params: map[string]interface{}{
				"client_id":     "foo.apps.googleusercontent.com",
				"client_secret": "foobar",
				"driver":        "",
				"realm":         "google",
				"scopes":        []string{"openid", "email", "profile"},
			},

			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				errors.ErrIdentityProviderConfig.WithArgs("driver name not found"),
			),
		},
		{
			name:   "test saml config validation error",
			driver: "jumpcloud",
			kind:   "saml",
			params: map[string]interface{}{
				"driver":    "",
				"realm":     "",
				"entity_id": "",
				"acs_urls":  "",
			},

			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				errors.ErrIdentityProviderConfigureRealmEmpty,
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewIdentityProviderConfig(tc.driver, tc.kind, tc.params)
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
				t.Errorf("NewIdentityProviderConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
