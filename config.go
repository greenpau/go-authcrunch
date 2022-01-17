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
	Portals     []*authn.PortalConfig `json:"auth_portal_config,omitempty" xml:"auth_portal_config,omitempty" yaml:"auth_portal_config,omitempty"`
	Policies    []*authz.PolicyConfig `json:"authz_policy_config,omitempty" xml:"authz_policy_config,omitempty" yaml:"authz_policy_config,omitempty"`
	credMap     map[string]*credentials.Config
}

// NewConfig returns an instance of Config.
func NewConfig() *Config {
	return &Config{
		credMap: make(map[string]*credentials.Config),
	}
}

// AddCredential adds a credential configuration.
func (cfg *Config) AddCredential(c interface{}) error {
	if cfg.Credentials == nil {
		cfg.Credentials = &credentials.Config{}
	}
	return cfg.Credentials.Add(c)
}

// AddAuthenticationPortal adds an authentication portal configuration.
func (cfg *Config) AddAuthenticationPortal(c *authn.PortalConfig) error {
	return nil
}

// AddAuthorizationPolicy adds an authorization policy configuration.
func (cfg *Config) AddAuthorizationPolicy(c *authz.PolicyConfig) error {
	return nil
}
