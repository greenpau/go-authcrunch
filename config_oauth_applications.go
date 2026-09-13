// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package authcrunch

import (
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

// AddOAuthApplication registers an independent, validated copy of application.
// Duplicate nicknames fail, including definitions with identical client values.
// This does not provision credentials or change any configured provider. Build a
// fresh Config on reload, using persisted registrations during directive parsing.
// Configuration mutations must not run concurrently with other Config accesses.
func (cfg *Config) AddOAuthApplication(application *oidc.OAuthApplicationConfig) error {
	applications, err := cfg.GetOAuthApplications()
	if err != nil {
		return err
	}
	if application == nil {
		return fmt.Errorf("oauth application is nil")
	}
	candidate, err := oidc.NewOAuthApplicationConfig(application.Name, application.Client)
	if err != nil {
		return err
	}
	if _, exists := applications[candidate.Name]; exists {
		return fmt.Errorf("duplicate oauth application nickname")
	}
	cfg.OAuthApplications = append(cfg.OAuthApplications, candidate)
	return nil
}

// GetOAuthApplication returns an independent copy of the registration with the
// exact nickname, or an error if absent. A previously persisted Config can supply
// this result to parser.NewOAuthApplicationConfigFromDirectives on reload.
func (cfg *Config) GetOAuthApplication(nickname string) (*oidc.OAuthApplicationConfig, error) {
	applications, err := cfg.GetOAuthApplications()
	if err != nil {
		return nil, err
	}
	client, exists := applications[nickname]
	if !exists {
		return nil, fmt.Errorf("oauth application not found")
	}
	return oidc.NewOAuthApplicationConfig(nickname, client)
}

// GetOAuthApplications validates all named registrations and returns independent
// client copies indexed by nickname for the public OIDC provider parser. Reads
// do not normalize or mutate Config; concurrent reads may share immutable input.
// This method and Config.Validate never generate missing credentials.
func (cfg *Config) GetOAuthApplications() (map[string]*oidc.ClientConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	applications := make(map[string]*oidc.ClientConfig, len(cfg.OAuthApplications))
	for i, application := range cfg.OAuthApplications {
		if application == nil {
			return nil, fmt.Errorf("oauth application at position %d is nil", i+1)
		}
		candidate, err := oidc.NewOAuthApplicationConfig(application.Name, application.Client)
		if err != nil {
			return nil, fmt.Errorf("invalid oauth application at position %d: %w", i+1, err)
		}
		if _, exists := applications[candidate.Name]; exists {
			return nil, fmt.Errorf("duplicate oauth application nickname at position %d", i+1)
		}
		applications[candidate.Name] = candidate.Client
	}
	return applications, nil
}

// ConfigureOIDCProvider connects an encoded provider body to portal using this
// Config's named applications. Collect all application blocks before calling it,
// independent of their textual order, then add the portal to Config as usual.
// The public parser resolves only explicit references before final validation.
// This configures one provider per portal, rejects a second definition, and does
// not modify Config or portal on error. No credentials or signing keys are made.
// Configure a fresh object graph before NewServer; this is not a live update API.
func (cfg *Config) ConfigureOIDCProvider(portal *authn.PortalConfig, statements []string) error {
	if portal == nil {
		return fmt.Errorf("portal config is nil")
	}
	applications, err := cfg.GetOAuthApplications()
	if err != nil {
		return err
	}
	provider, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, applications)
	if err != nil {
		return err
	}
	return portal.ConfigureOIDCProvider(provider)
}
