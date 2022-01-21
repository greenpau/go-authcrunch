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

package aaasf

import (
	"github.com/greenpau/aaasf/pkg/authn"
	"github.com/greenpau/aaasf/pkg/authz"
	"github.com/greenpau/aaasf/pkg/credentials"
)

// Config is a configuration of Server.
type Config struct {
	Credentials *credentials.Config   `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	Portals     []*authn.PortalConfig `json:"auth_portal_configs,omitempty" xml:"auth_portal_configs,omitempty" yaml:"auth_portal_configs,omitempty"`
	Policies    []*authz.PolicyConfig `json:"authz_policy_configs,omitempty" xml:"authz_policy_configs,omitempty" yaml:"authz_policy_configs,omitempty"`
}

// NewConfig returns an instance of Config.
func NewConfig() *Config {
	return &Config{}
}

// AddCredential adds a credential configuration.
func (cfg *Config) AddCredential(c credentials.Credential) error {
	if cfg.Credentials == nil {
		cfg.Credentials = &credentials.Config{}
	}
	return cfg.Credentials.Add(c)
}

// AddAuthenticationPortal adds an authentication portal configuration.
func (cfg *Config) AddAuthenticationPortal(p *authn.PortalConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg.Portals = append(cfg.Portals, p)
	return nil
}

// AddAuthorizationPolicy adds an authorization policy configuration.
func (cfg *Config) AddAuthorizationPolicy(p *authz.PolicyConfig) error {
	cfg.Policies = append(cfg.Policies, p)
	return nil
}

// Validate validates Config.
func (cfg *Config) Validate() error {
	for _, portal := range cfg.Portals {
		if err := portal.Validate(); err != nil {
			return err
		}
	}
	return nil
}
