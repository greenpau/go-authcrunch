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

package registry

import (
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

// UserRegistryConfig represents a common set of configuration settings for user registration
type UserRegistryConfig struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	// The switch determining whether the registration is enabled/disabled.
	Disabled bool `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	// The title of the registration page
	Title string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	// The mandatory registration code. It is possible adding multiple
	// codes, comma separated.
	Code string `json:"code,omitempty" xml:"code,omitempty" yaml:"code,omitempty"`
	// The file path to registration database.
	Dropbox string `json:"dropbox,omitempty" xml:"dropbox,omitempty" yaml:"dropbox,omitempty"`
	// The switch determining whether a user must accept terms and conditions
	RequireAcceptTerms bool `json:"require_accept_terms,omitempty" xml:"require_accept_terms,omitempty" yaml:"require_accept_terms,omitempty"`
	// The switch determining whether the domain associated with an email has
	// a valid MX DNS record.
	RequireDomainMailRecord bool `json:"require_domain_mx,omitempty" xml:"require_domain_mx,omitempty" yaml:"require_domain_mx,omitempty"`
	// The link to terms and conditions document.
	TermsConditionsLink string `json:"terms_conditions_link,omitempty" xml:"terms_conditions_link,omitempty" yaml:"terms_conditions_link,omitempty"`
	// The link to privacy policy document.
	PrivacyPolicyLink string `json:"privacy_policy_link,omitempty" xml:"privacy_policy_link,omitempty" yaml:"privacy_policy_link,omitempty"`
	// The email provider used for the notifications.
	EmailProvider string `json:"email_provider,omitempty" xml:"email_provider,omitempty" yaml:"email_provider,omitempty"`
	// The email address(es) of portal administrators.
	AdminEmails []string `json:"admin_emails,omitempty" xml:"admin_emails,omitempty" yaml:"admin_emails,omitempty"`
	// The name of the identity store associated with the Config.
	IdentityStore string `json:"identity_store,omitempty" xml:"identity_store,omitempty" yaml:"identity_store,omitempty"`

	credentials *credentials.Config `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	messaging   *messaging.Config   `json:"messaging,omitempty" xml:"messaging,omitempty" yaml:"messaging,omitempty"`
}

// Validate validates user registration configuration.
func (cfg *UserRegistryConfig) Validate() error {
	if cfg.Name == "" {
		return errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, "name is not set")
	}
	if cfg.Dropbox == "" {
		return errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, "dropbox is not set")
	}
	if cfg.EmailProvider == "" {
		return errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, "email provider is not set")
	}
	if len(cfg.AdminEmails) < 1 {
		return errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, "admin email address is not set")
	}
	if cfg.Title == "" {
		cfg.Title = "Sign Up"
	}
	if cfg.IdentityStore == "" {
		return errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, "identity store name is not set")
	}
	return nil
}

// SetCredentials binds to shared credentials.
func (cfg *UserRegistryConfig) SetCredentials(c *credentials.Config) {
	cfg.credentials = c
	return
}

// SetMessaging binds to messaging config.
func (cfg *UserRegistryConfig) SetMessaging(c *messaging.Config) {
	cfg.messaging = c
	return
}

// ValidateMessaging validates messaging provider and credentials used for
// the user registration.
func (cfg *UserRegistryConfig) ValidateMessaging() error {
	if cfg.messaging == nil {
		return errors.ErrUserRegistryConfigMessagingNil.WithArgs(cfg.Name)
	}
	if found := cfg.messaging.FindProvider(cfg.EmailProvider); !found {
		return errors.ErrUserRegistryConfigMessagingProviderNotFound.WithArgs(cfg.Name)
	}

	providerType := cfg.messaging.GetProviderType(cfg.EmailProvider)

	if providerType == "email" {
		providerCreds := cfg.messaging.FindProviderCredentials(cfg.EmailProvider)
		if providerCreds == "" {
			return errors.ErrUserRegistryConfigMessagingProviderCredentialsNotFound.WithArgs(cfg.Name, cfg.EmailProvider)
		}

		if providerCreds != "passwordless" {
			if cfg.credentials == nil {
				return errors.ErrUserRegistryConfigCredentialsNil.WithArgs(cfg.Name)
			}
			if found := cfg.credentials.FindCredential(providerCreds); !found {
				return errors.ErrUserRegistryConfigCredentialsNotFound.WithArgs(cfg.Name, providerCreds)
			}
		}
	}
	return nil
}
