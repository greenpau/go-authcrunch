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
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"testing"
)

func TestNewIdentityProvider(t *testing.T) {
	testcases := []struct {
		name          string
		config        *IdentityProviderConfig
		disableLogger bool
		want          string
		shouldErr     bool
		err           error
	}{
		{
			name: "test oauth identity provider",
			config: &IdentityProviderConfig{
				Name: "contoso",
				Kind: "oauth",
				Params: map[string]interface{}{
					"driver":        "generic",
					"realm":         "contoso",
					"client_id":     "foo",
					"client_secret": "bar",
					"base_auth_url": "https://localhost/oauth",
					"metadata_url":  "https://localhost/oauth/.well-known/openid-configuration",
				},
			},
			want: `{
			  "name": "contoso",
			  "kind": "oauth",
			  "realm": "contoso"
            }`,
		},
		{
			name: "test saml identity provider",
			config: &IdentityProviderConfig{
				Name: "jumpcloud",
				Kind: "saml",
				Params: map[string]interface{}{
					"realm":                  "jumpcloud",
					"driver":                 "generic",
					"idp_metadata_location":  "JumpCloud-saml2-metadata.xml",
					"idp_sign_cert_location": "certificate.pem",
					"idp_login_url":          "https://sso.jumpcloud.com/saml2/authp",
					"application_name":       "Auth Portal",
					"entity_id":              "urn:authp",
					"acs_urls": []string{
						"https://localhost/saml/jumpcloud",
					},
				},
			},
			want: `{
			  "name": "jumpcloud",
              "kind": "saml",
              "realm": "jumpcloud"
			}`,
		},
		{
			name: "test logger nil error",
			config: &IdentityProviderConfig{
				Name: "default",
				Kind: "local",
				Params: map[string]interface{}{
					"path":  "foo",
					"realm": "local",
				},
			},
			disableLogger: true,
			shouldErr:     true,
			err:           errors.ErrIdentityProviderConfigureLoggerNotFound,
		},
		{
			name: "test config validation error",
			config: &IdentityProviderConfig{
				Kind: "local",
				Params: map[string]interface{}{
					"path":  "foo",
					"realm": "local",
				},
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfigInvalid.WithArgs(
				"empty identity provider name",
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

			st, err := NewIdentityProvider(tc.config, logger)
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
				t.Errorf("NewIdentityProvider() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
