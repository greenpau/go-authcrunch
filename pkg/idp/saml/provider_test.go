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

package saml

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"testing"
)

func TestNewIdentityProvider(t *testing.T) {
	testcases := []struct {
		name      string
		config    *Config
		logger    *zap.Logger
		want      map[string]interface{}
		shouldErr bool
		errPhase  string
		err       error
	}{
		{
			name: "jumpcloud saml provider",
			config: &Config{
				Name:                "jumpcloud",
				Realm:               "jumpcloud",
				Driver:              "generic",
				IdpMetadataLocation: "../../../testdata/saml/jumpcloud/JumpCloud-saml2-metadata.xml",
				IdpSignCertLocation: "../../../testdata/saml/jumpcloud/certificate.pem",
				IdpLoginURL:         "https://sso.jumpcloud.com/saml2/authp",
				ApplicationName:     "Auth Portal",
				EntityID:            "urn:authp",
				AssertionConsumerServiceURLs: []string{
					"https://localhost/saml/jumpcloud",
				},
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"name":  "jumpcloud",
				"kind":  "saml",
				"realm": "jumpcloud",
				"config": map[string]interface{}{
					"acs_urls": []interface{}{
						"https://localhost/saml/jumpcloud",
					},
					"application_name":       "Auth Portal",
					"entity_id":              "urn:authp",
					"idp_login_url":          "https://sso.jumpcloud.com/saml2/authp",
					"idp_metadata_location":  "../../../testdata/saml/jumpcloud/JumpCloud-saml2-metadata.xml",
					"idp_sign_cert_location": "../../../testdata/saml/jumpcloud/certificate.pem",
					"name":                   "jumpcloud",
					"driver":                 "generic",
					"realm":                  "jumpcloud",
				},
			},
		},
		{
			name: "azure saml provider",
			config: &Config{
				Name:                "azure",
				Realm:               "azure",
				Driver:              "azure",
				IdpMetadataLocation: "../../../testdata/saml/azure/metadata.xml",
				IdpSignCertLocation: "../../../testdata/saml/azure/certificate.pem",
				TenantID:            "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
				ApplicationID:       "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
				ApplicationName:     "My Gatekeeper",
				EntityID:            "urn:caddy:mygatekeeper",
				AssertionConsumerServiceURLs: []string{
					"https://localhost/auth/saml/azure",
				},
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"name":  "azure",
				"kind":  "saml",
				"realm": "azure",
				"config": map[string]interface{}{
					"acs_urls": []interface{}{
						"https://localhost/auth/saml/azure",
					},

					"application_id":         "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
					"application_name":       "My Gatekeeper",
					"entity_id":              "urn:caddy:mygatekeeper",
					"idp_login_url":          "https://account.activedirectory.windowsazure.com/applications/signin/My Gatekeeper/623cae7c-e6b2-43c5-853c-2059c9b2cb58?tenantId=1b9e886b-8ff2-4378-b6c8-6771259a5f51",
					"idp_metadata_location":  "../../../testdata/saml/azure/metadata.xml",
					"idp_sign_cert_location": "../../../testdata/saml/azure/certificate.pem",
					"name":                   "azure",
					"driver":                 "azure",
					"realm":                  "azure",
					"tenant_id":              "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
				},
			},
		},
		{
			name: "test nil logger",
			config: &Config{
				Realm: "azure",
			},
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityProviderConfigureLoggerNotFound,
		},
		{
			name: "test invalid config",
			config: &Config{
				Realm: "azure",
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityProviderConfigureNameEmpty,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			prv, err := NewIdentityProvider(tc.config, tc.logger)
			if tc.errPhase == "initialize" {
				if tests.EvalErrWithLog(t, err, "NewIdentityProvider", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "NewIdentityProvider", false, nil, msgs) {
					return
				}
			}

			err = prv.Configure()
			if tc.errPhase == "configure" {
				if tests.EvalErrWithLog(t, err, "IdentityProvider.Configure", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "IdentityProvider.Configure", false, nil, msgs) {
					return
				}
			}

			got["name"] = prv.GetName()
			got["realm"] = prv.GetRealm()
			got["kind"] = prv.GetKind()
			got["config"] = prv.GetConfig()

			tests.EvalObjectsWithLog(t, "IdentityProvider", tc.want, got, msgs)
		})
	}
}
