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
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// Config holds the configuration for the IdentityProvider.
type Config struct {
	// Name is the unique name associated with the IdentityProvider.
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	// Realm the authentication realm associated with the IdentityProvider.
	Realm string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	// Driver is the name of the driver associated with the IdentityProvider, e.g. azure.
	Driver string `json:"driver,omitempty" xml:"driver,omitempty" yaml:"driver,omitempty"`
	// IdpMetadataLocation is the path to the Identity Provider metadata.
	IdpMetadataLocation string `json:"idp_metadata_location,omitempty" xml:"idp_metadata_location,omitempty" yaml:"idp_metadata_location,omitempty"`
	// IdpSignCertLocation is the path to the Identity Provider signing certificate.
	IdpSignCertLocation string `json:"idp_sign_cert_location,omitempty" xml:"idp_sign_cert_location,omitempty" yaml:"idp_sign_cert_location,omitempty"`
	// IdpLoginURL is the SAML authentication endpoint with the Identity Provider.
	IdpLoginURL string `json:"idp_login_url,omitempty" xml:"idp_login_url,omitempty" yaml:"idp_login_url,omitempty"`
	// TenantID is the tenant ID associated with the IdentityProvider.
	TenantID string `json:"tenant_id,omitempty" xml:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	// ApplicationID is the application ID associated with the IdentityProvider.
	ApplicationID string `json:"application_id,omitempty" xml:"application_id,omitempty" yaml:"application_id,omitempty"`
	// ApplicationName  is the application name associated with the IdentityProvider.
	ApplicationName string `json:"application_name,omitempty" xml:"application_name,omitempty" yaml:"application_name,omitempty"`
	// EntityID is the "Identifier (Entity ID)" an administrator
	// specifies in "Set up Single Sign-On with SAML" in Azure AD
	// Enterprise Applications.
	EntityID string `json:"entity_id,omitempty" xml:"entity_id,omitempty" yaml:"entity_id,omitempty"`
	// AssertionConsumerServiceURLs is the list of URLs server instance is listening
	// on. These URLs are known as SP Assertion Consumer Service endpoints. For
	// example, users may access a website via http://app.domain.local. At the
	// same time the users may access it by IP, e.g. http://10.10.10.10. or
	// by name, i.e. app. Each of the URLs is a separate endpoint.
	AssertionConsumerServiceURLs []string `json:"acs_urls,omitempty" xml:"acs_urls,omitempty" yaml:"acs_urls,omitempty"`

	TLSInsecureSkipVerify bool `json:"tls_insecure_skip_verify,omitempty" xml:"tls_insecure_skip_verify,omitempty" yaml:"tls_insecure_skip_verify,omitempty"`

	// LoginIcon is the UI login icon attributes.
	LoginIcon *icons.LoginIcon `json:"login_icon,omitempty" xml:"login_icon,omitempty" yaml:"login_icon,omitempty"`
}

// Validate validates identity store configuration.
func (cfg *Config) Validate() error {
	if cfg.Name == "" {
		return errors.ErrIdentityProviderConfigureNameEmpty
	}
	if cfg.Realm == "" {
		return errors.ErrIdentityProviderConfigureRealmEmpty
	}

	switch cfg.Driver {
	case "azure":
		if cfg.TenantID == "" {
			return errors.ErrIdentityProviderConfig.WithArgs("no tenant id found")
		}
		if cfg.ApplicationID == "" {
			return errors.ErrIdentityProviderConfig.WithArgs("no application id found")
		}
		if cfg.ApplicationName == "" {
			return errors.ErrIdentityProviderConfig.WithArgs("no application name found")
		}
		if cfg.IdpMetadataLocation == "" {
			cfg.IdpMetadataLocation = fmt.Sprintf(
				"https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml",
				cfg.TenantID,
			)
		}
		cfg.IdpLoginURL = fmt.Sprintf(
			"https://account.activedirectory.windowsazure.com/applications/signin/%s/%s?tenantId=%s",
			cfg.ApplicationName, cfg.ApplicationID, cfg.TenantID,
		)
	case "generic":
	case "":
		return errors.ErrIdentityProviderConfig.WithArgs("no SAML provider found")
	default:
		return errors.ErrIdentityProviderConfig.WithArgs(
			fmt.Errorf("driver %q is unsupported", cfg.Driver),
		)
	}

	if cfg.IdpLoginURL == "" {
		return errors.ErrIdentityProviderConfig.WithArgs("IdP Loging URL not found")
	}

	if len(cfg.AssertionConsumerServiceURLs) < 1 {
		return errors.ErrIdentityProviderConfig.WithArgs("ACS URLs are missing")
	}

	if cfg.IdpSignCertLocation == "" {
		return errors.ErrIdentityProviderConfig.WithArgs("IdP Signing Certificate not found")
	}

	// Configure UI login icon.
	if cfg.LoginIcon == nil {
		cfg.LoginIcon = icons.NewLoginIcon(cfg.Driver)
	} else {
		cfg.LoginIcon.Configure(cfg.Driver)
	}

	return nil
}
