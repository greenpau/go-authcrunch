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
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/idp/saml"
)

// IdentityProviderConfig represents an identity provider configuration.
type IdentityProviderConfig struct {
	Name   string                 `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Kind   string                 `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	Params map[string]interface{} `json:"params,omitempty" xml:"params,omitempty" yaml:"params,omitempty"`
}

// NewIdentityProviderConfig returns IdentityProviderConfig instance.
func NewIdentityProviderConfig(name, kind string, params map[string]interface{}) (*IdentityProviderConfig, error) {
	cfg := &IdentityProviderConfig{
		Name:   name,
		Kind:   kind,
		Params: params,
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate validates identity provider config.
func (cfg *IdentityProviderConfig) Validate() error {
	var requiredFields, optionalFields []string
	if cfg.Name == "" {
		return errors.ErrIdentityProviderConfigInvalid.WithArgs("empty identity provider name")
	}

	switch cfg.Kind {
	case "oauth":
		requiredFields = []string{
			"realm",
			"driver",
		}
		optionalFields = []string{
			"tenant_id",
			"domain_name",
			"client_id",
			"client_secret",
			"server_id",
			"base_auth_url",
			"metadata_url",
			"identity_token_name",
			"authorization_url",
			"token_url",
			// Disabled features.
			"metadata_discovery_disabled",
			"key_verification_disabled",
			"pass_grant_type_disabled",
			"response_type_disabled",
			"scope_disabled",
			"nonce_disabled",
			// Enabled features.
			"accept_header_enabled",
			"js_callback_enabled",
			"logout_enabled",
			// Retry and delay.
			"delay_start",
			"retry_attempts",
			"retry_interval",
			// AWS Cognito.
			"user_pool_id",
			"region",
			// ID Token.
			"identity_token_cookie_enabled",
			"identity_token_cookie_name",
			// Misc.
			"required_token_fields",
			"scopes",
			"user_group_filters",
			"user_org_filters",
			"response_type",
			"jwks_keys",
			"tls_insecure_skip_verify",
			"email_claim_check_disabled",
			"login_icon",
			"user_info_fields",
		}
	case "saml":
		requiredFields = []string{
			"realm",
			"driver",
			"entity_id",
			"acs_urls",
		}
		optionalFields = []string{
			"idp_metadata_location",
			"idp_sign_cert_location",
			"idp_login_url",
			"tenant_id",
			"application_id",
			"application_name",
			"tls_insecure_skip_verify",
			"login_icon",
		}
	case "":
		return errors.ErrIdentityProviderConfigInvalid.WithArgs("empty identity provider type")
	default:
		return errors.ErrIdentityProviderConfigInvalid.WithArgs("unsupported identity provider type " + cfg.Kind)
	}

	if err := validateFields(cfg.Params, requiredFields, optionalFields); err != nil {
		return errors.ErrIdentityProviderConfigInvalid.WithArgs(err)
	}

	b, _ := json.Marshal(cfg.Params)
	switch cfg.Kind {
	case "oauth":
		config := &oauth.Config{}
		json.Unmarshal(b, config)
		config.Name = cfg.Name
		if err := config.Validate(); err != nil {
			return errors.ErrIdentityProviderConfigInvalid.WithArgs(err)
		}
	case "saml":
		config := &saml.Config{}
		json.Unmarshal(b, config)
		config.Name = cfg.Name
		if err := config.Validate(); err != nil {
			return errors.ErrIdentityProviderConfigInvalid.WithArgs(err)
		}
	}

	return nil
}

func validateFields(m map[string]interface{}, requiredFields, optionalFields []string) error {
	if m == nil || len(m) == 0 {
		return fmt.Errorf("empty identity provider parameters")
	}

	for _, k := range requiredFields {
		if _, exists := m[k]; !exists {
			return fmt.Errorf("required field %q not found", k)
		}
	}

	allFields := append(optionalFields, requiredFields...)
	for k := range m {
		var found bool
		for _, f := range allFields {
			if f == k {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("found unsupported %q field", k)
		}
	}

	return nil
}
