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

package ids

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/ids/ldap"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
)

// IdentityStoreConfig represents an identity store configuration.
type IdentityStoreConfig struct {
	Name   string                 `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Kind   string                 `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	Params map[string]interface{} `json:"params,omitempty" xml:"params,omitempty" yaml:"params,omitempty"`
}

// NewIdentityStoreConfig returns IdentityStoreConfig instance.
func NewIdentityStoreConfig(name, kind string, params map[string]interface{}) (*IdentityStoreConfig, error) {
	cfg := &IdentityStoreConfig{
		Name:   name,
		Kind:   kind,
		Params: params,
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate validates identity store config.
func (cfg *IdentityStoreConfig) Validate() error {
	var requiredFields, optionalFields []string
	if cfg.Name == "" {
		return errors.ErrIdentityStoreConfigInvalid.WithArgs("empty identity store name")
	}

	switch cfg.Kind {
	case "local":
		requiredFields = []string{
			"realm",
			"path",
		}
		optionalFields = []string{
			"users",
			"login_icon",
			"registration_enabled",
			"username_recovery_enabled",
			"password_recovery_enabled",
			"contact_support_enabled",
			"support_link",
			"support_email",
		}
	case "ldap":
		requiredFields = []string{
			"realm",
			"servers",
			"groups",
		}
		optionalFields = []string{
			"bind_username",
			"bind_password",
			"attributes",
			"trusted_authorities",
			"search_base_dn",
			"search_user_filter",
			"search_group_filter",
			"login_icon",
			"registration_enabled",
			"username_recovery_enabled",
			"password_recovery_enabled",
			"contact_support_enabled",
			"support_link",
			"support_email",
			"fallback_roles",
		}
	case "":
		return errors.ErrIdentityStoreConfigInvalid.WithArgs("empty identity store type")
	default:
		return errors.ErrIdentityStoreConfigInvalid.WithArgs("unsupported identity store type " + cfg.Kind)
	}

	if err := validateFields(cfg.Params, requiredFields, optionalFields); err != nil {
		return errors.ErrIdentityStoreConfigInvalid.WithArgs(err)
	}

	b, _ := json.Marshal(cfg.Params)
	switch cfg.Kind {
	case "local":
		config := &local.Config{}
		json.Unmarshal(b, config)
		config.Name = cfg.Name
		if err := config.Validate(); err != nil {
			return errors.ErrIdentityProviderConfigInvalid.WithArgs(err)
		}
	case "ldap":
		config := &ldap.Config{}
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
		return fmt.Errorf("empty identity store parameters")
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
