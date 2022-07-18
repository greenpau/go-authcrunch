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
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// SingleSignOnProviderConfig represents an identity provider configuration.
type SingleSignOnProviderConfig struct {
	Name           string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Driver         string   `json:"driver,omitempty" xml:"driver,omitempty" yaml:"driver,omitempty"`
	EntityID       string   `json:"entity_id,omitempty" xml:"entity_id,omitempty" yaml:"entity_id,omitempty"`
	Locations      []string `json:"locations,omitempty" xml:"locations,omitempty" yaml:"locations,omitempty"`
	PrivateKeyPath string   `json:"private_key_path,omitempty" xml:"private_key_path,omitempty" yaml:"private_key_path,omitempty"`
	CertPath       string   `json:"cert_path,omitempty" xml:"cert_path,omitempty" yaml:"cert_path,omitempty"`
}

// NewSingleSignOnProviderConfig returns SingleSignOnProviderConfig instance.
func NewSingleSignOnProviderConfig(data map[string]interface{}) (*SingleSignOnProviderConfig, error) {

	requiredFields := []string{"name", "entity_id", "locations", "private_key_path", "cert_path"}
	optionalFields := []string{"driver"}

	if err := validateFields(data, requiredFields, optionalFields); err != nil {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("input data error", err)
	}

	b, _ := json.Marshal(data)
	cfg := &SingleSignOnProviderConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("json.Unmarshal error", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate validates identity provider config.
func (cfg *SingleSignOnProviderConfig) Validate() error {
	if cfg.Name == "" {
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty provider name")
	}
	if cfg.EntityID == "" {
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty entity id")
	}
	if cfg.PrivateKeyPath == "" {
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty private key path")
	}
	if cfg.CertPath == "" {
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty cert path")
	}
	if len(cfg.Locations) < 1 {
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty locations")
	}
	switch cfg.Driver {
	case "aws":
	case "":
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "empty driver name")
	default:
		return errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("misconfiguration", "unsupported driver name")
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
