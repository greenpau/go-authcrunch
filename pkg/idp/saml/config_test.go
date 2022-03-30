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
	"testing"
)

var (
	// Jumpcloud config has no TenantID, ApplicationID fields.
	testConfig1 = &Config{
		Name:                "jumpcloud",
		Realm:               "jumpcloud",
		Driver:              "generic",
		IdpMetadataLocation: "JumpCloud-saml2-metadata.xml",
		IdpSignCertLocation: "certificate.pem",
		IdpLoginURL:         "https://sso.jumpcloud.com/saml2/authp",
		ApplicationName:     "Auth Portal",
		EntityID:            "urn:authp",
		AssertionConsumerServiceURLs: []string{
			"https://localhost/saml/jumpcloud",
		},
	}
	// Azure config has no IdpLoginURL field.
	testConfig2 = &Config{
		Name:                "azure",
		Realm:               "azure",
		Driver:              "azure",
		IdpMetadataLocation: "azure_ad_app_metadata.xml",
		IdpSignCertLocation: "azure_ad_app_signing_cert.pem",
		TenantID:            "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
		ApplicationID:       "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
		ApplicationName:     "My Gatekeeper",
		EntityID:            "urn:caddy:mygatekeeper",
		AssertionConsumerServiceURLs: []string{
			"https://localhost/auth/saml/azure",
		},
	}

	testConfig3 = &Config{
		Name:                "azure",
		Realm:               "azure",
		Driver:              "azure",
		IdpSignCertLocation: "azure_ad_app_signing_cert.pem",
		TenantID:            "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
		ApplicationID:       "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
		ApplicationName:     "My Gatekeeper",
		EntityID:            "urn:caddy:mygatekeeper",
		AssertionConsumerServiceURLs: []string{
			"https://localhost/auth/saml/azure",
		},
	}
)

func TestValidateConfig(t *testing.T) {
	testcases := []struct {
		name      string
		config    *Config
		shouldErr bool
		err       error
	}{
		{
			name:   "validate jumpcloud saml config",
			config: testConfig1,
		},
		{
			name:   "validate azure saml config",
			config: testConfig2,
		},
		{
			name:   "validate azure saml config without idp metadata location",
			config: testConfig3,
		},
		{
			name: "test empty config name",
			config: &Config{
				Realm: "azure",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigureNameEmpty,
		},
		{
			name: "test empty config realm",
			config: &Config{
				Name: "azure",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigureRealmEmpty,
		},
		{
			name: "test config tenant id not found",
			config: &Config{
				Name:   "azure",
				Realm:  "azure",
				Driver: "azure",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("no tenant id found"),
		},
		{
			name: "test config application id not found",
			config: &Config{
				Name:     "azure",
				Realm:    "azure",
				Driver:   "azure",
				TenantID: "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("no application id found"),
		},
		{
			name: "test config application name not found",
			config: &Config{
				Name:          "azure",
				Realm:         "azure",
				Driver:        "azure",
				TenantID:      "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
				ApplicationID: "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("no application name found"),
		},
		{
			name: "test config SAML provider not found",
			config: &Config{
				Name:            "azure",
				Realm:           "azure",
				Driver:          "",
				TenantID:        "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
				ApplicationID:   "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
				ApplicationName: "My Gatekeeper",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("no SAML provider found"),
		},
		{
			name: "test config SAML provider unsupported",
			config: &Config{
				Name:            "azure",
				Realm:           "azure",
				Driver:          "foobar",
				TenantID:        "1b9e886b-8ff2-4378-b6c8-6771259a5f51",
				ApplicationID:   "623cae7c-e6b2-43c5-853c-2059c9b2cb58",
				ApplicationName: "My Gatekeeper",
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf("driver %q is unsupported", "foobar"),
			),
		},
		{
			name: "test config IdP Loging URL not found",
			config: &Config{
				Name:   "jumpcloud",
				Realm:  "jumpcloud",
				Driver: "generic",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("IdP Loging URL not found"),
		},
		{
			name: "test config ACS URLs not found",
			config: &Config{
				Name:        "jumpcloud",
				Realm:       "jumpcloud",
				Driver:      "generic",
				IdpLoginURL: "https://sso.jumpcloud.com/saml2/authp",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("ACS URLs are missing"),
		},
		{
			name: "test config IdP Signing Certificate not found",
			config: &Config{
				Name:        "jumpcloud",
				Realm:       "jumpcloud",
				Driver:      "generic",
				IdpLoginURL: "https://sso.jumpcloud.com/saml2/authp",
				AssertionConsumerServiceURLs: []string{
					"https://localhost/saml/jumpcloud",
				},
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("IdP Signing Certificate not found"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			tests.EvalErrWithLog(t, tc.config.Validate(), "ValidateConfig", tc.shouldErr, tc.err, msgs)
		})
	}
}
