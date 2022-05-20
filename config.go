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

package authcrunch

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
)

// Config is a configuration of Server.
type Config struct {
	Credentials               *credentials.Config           `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	Messaging                 *messaging.Config             `json:"messaging,omitempty" xml:"messaging,omitempty" yaml:"messaging,omitempty"`
	AuthenticationPortals     []*authn.PortalConfig         `json:"authentication_portals,omitempty" xml:"authentication_portals,omitempty" yaml:"authentication_portals,omitempty"`
	AuthorizationPolicies     []*authz.PolicyConfig         `json:"authorization_policies,omitempty" xml:"authorization_policies,omitempty" yaml:"authorization_policies,omitempty"`
	IdentityStores            []*ids.IdentityStoreConfig    `json:"identity_stores,omitempty" xml:"identity_stores,omitempty" yaml:"identity_stores,omitempty"`
	IdentityProviders         []*idp.IdentityProviderConfig `json:"identity_providers,omitempty" xml:"identity_providers,omitempty" yaml:"identity_providers,omitempty"`
	disabledIdentityStores    map[string]interface{}
	disabledIdentityProviders map[string]interface{}
	UserRegistries            []*registry.UserRegistryConfig `json:"user_registries,omitempty" xml:"user_registries,omitempty" yaml:"user_registries,omitempty"`
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

// AddMessagingProvider adds a messaging provider configuration.
func (cfg *Config) AddMessagingProvider(p messaging.Provider) error {
	if cfg.Messaging == nil {
		cfg.Messaging = &messaging.Config{}
	}
	return cfg.Messaging.Add(p)
}

// AddIdentityStore adds an identity store configuration.
func (cfg *Config) AddIdentityStore(name, kind string, data map[string]interface{}) error {
	store, err := ids.NewIdentityStoreConfig(name, kind, data)
	if err != nil {
		return err
	}
	cfg.IdentityStores = append(cfg.IdentityStores, store)
	return nil
}

// AddIdentityProvider adds an identity provider configuration.
func (cfg *Config) AddIdentityProvider(name, kind string, data map[string]interface{}) error {
	provider, err := idp.NewIdentityProviderConfig(name, kind, data)
	if err != nil {
		return err
	}
	cfg.IdentityProviders = append(cfg.IdentityProviders, provider)
	return nil
}

// AddAuthenticationPortal adds an authentication portal configuration.
func (cfg *Config) AddAuthenticationPortal(p *authn.PortalConfig) error {
	if err := p.Validate(); err != nil {
		return err
	}
	cfg.AuthenticationPortals = append(cfg.AuthenticationPortals, p)
	return nil
}

// AddAuthorizationPolicy adds an authorization policy configuration.
func (cfg *Config) AddAuthorizationPolicy(p *authz.PolicyConfig) error {
	if err := p.Validate(); err != nil {
		return err
	}
	cfg.AuthorizationPolicies = append(cfg.AuthorizationPolicies, p)
	return nil
}

// Validate validates Config.
func (cfg *Config) Validate() error {
	if len(cfg.AuthenticationPortals) < 1 && len(cfg.AuthorizationPolicies) < 1 {
		return fmt.Errorf("no portals and gatekeepers found")
	}

	identityStoreUserRegistry := make(map[string]string)
	for _, userRegistry := range cfg.UserRegistries {
		userRegistry.SetCredentials(cfg.Credentials)
		userRegistry.SetMessaging(cfg.Messaging)
		if err := userRegistry.ValidateMessaging(); err != nil {
			return err
		}
		var identityStoreFound bool
		for _, identityStore := range cfg.IdentityStores {
			if identityStore.Name == userRegistry.IdentityStore {
				identityStoreFound = true
				identityStoreUserRegistry[identityStore.Name] = userRegistry.IdentityStore
				break
			}
		}
		if !identityStoreFound {
			return fmt.Errorf(
				"identity store %q referenced in %q user registry not found",
				userRegistry.IdentityStore, userRegistry.Name,
			)
		}
	}

	// Validate auth portal configurations.
	for _, portalCfg := range cfg.AuthenticationPortals {
		// If there are no excplicitly specified identity stores and providers in a portal, add all of them.
		if len(portalCfg.IdentityStores) == 0 && len(portalCfg.IdentityProviders) == 0 {
			for _, entry := range cfg.IdentityStores {
				portalCfg.IdentityStores = append(portalCfg.IdentityStores, entry.Name)
			}
			for _, entry := range cfg.IdentityProviders {
				portalCfg.IdentityProviders = append(portalCfg.IdentityProviders, entry.Name)
			}
		}

		if len(portalCfg.IdentityStores) == 0 && len(portalCfg.IdentityProviders) == 0 {
			return errors.ErrPortalConfigBackendsNotFound
		}

		// Filter out disabled identity store names.
		portalCfg.IdentityStores = cfg.filterDisabledIdentityStores(portalCfg.IdentityStores)

		// Vealidate that there are no duplicate or overlapping identity store and providers.
		authByName := make(map[string]string)
		authByRealm := make(map[string]string)

		for _, storeName := range portalCfg.IdentityStores {
			if v, exists := authByName[storeName]; exists {
				return fmt.Errorf(
					"identity store %q has the same name as %s",
					storeName, v,
				)
			}

			authByName[storeName] = "another identity store"

			var storeConfig *ids.IdentityStoreConfig
			for _, entry := range cfg.IdentityStores {
				storeConfig = entry
				if entry.Name == storeName {
					break
				}
			}
			if storeConfig == nil {
				continue
			}
			if storeConfig.Params == nil {
				continue
			}
			if v, exists := storeConfig.Params["realm"]; exists {
				realmName := v.(string)
				if prevStoreName, exists := authByRealm[realmName]; exists {
					return fmt.Errorf(
						"identity provider %q has the same %q realm as %q",
						storeName, realmName, prevStoreName,
					)
				}
				authByRealm[realmName] = storeName
				authByName[storeName] = "identity store in " + realmName + " realm"
			}

			// Add registry store if configured.
			if v, exists := identityStoreUserRegistry[storeName]; exists {
				storeConfig.Params["registration_enabled"] = true
				portalCfg.UserRegistries = append(portalCfg.UserRegistries, v)
			}
		}

		// Filter out disabled identity store names.
		portalCfg.IdentityProviders = cfg.filterDisabledIdentityProviders(portalCfg.IdentityProviders)

		for _, providerName := range portalCfg.IdentityProviders {
			if v, exists := authByName[providerName]; exists {
				return fmt.Errorf(
					"identity provider %q has the same name as %s",
					providerName, v,
				)
			}

			authByName[providerName] = "another identity provider"

			var providerConfig *idp.IdentityProviderConfig
			for _, entry := range cfg.IdentityProviders {
				providerConfig = entry
				if entry.Name == providerName {
					break
				}
			}
			if providerConfig == nil {
				continue
			}
			if providerConfig.Params == nil {
				continue
			}
			if v, exists := providerConfig.Params["realm"]; exists {
				realmName := v.(string)
				if prevProviderName, exists := authByRealm[realmName]; exists {
					return fmt.Errorf(
						"identity provider %q has the same %q realm as %q",
						providerName, realmName, prevProviderName,
					)
				}
				authByRealm[realmName] = providerName
				authByName[providerName] = "identity provider in " + realmName + " realm"
			}
		}
	}

	return nil
}

// AddDisabledIdentityStore adds the names of disabled identity stores.
func (cfg *Config) AddDisabledIdentityStore(s string) {
	if cfg.disabledIdentityStores == nil {
		cfg.disabledIdentityStores = map[string]interface{}{
			s: true,
		}
		return
	}
	cfg.disabledIdentityStores[s] = true
}

// AddDisabledIdentityProvider adds the names of disabled identity providers.
func (cfg *Config) AddDisabledIdentityProvider(s string) {
	if cfg.disabledIdentityProviders == nil {
		cfg.disabledIdentityProviders = map[string]interface{}{
			s: true,
		}
		return
	}
	cfg.disabledIdentityProviders[s] = true
}

func (cfg *Config) filterDisabledIdentityStores(arr []string) []string {
	var output []string
	if len(arr) == 0 || cfg.disabledIdentityStores == nil {
		return arr
	}
	for _, s := range arr {
		if _, exists := cfg.disabledIdentityStores[s]; exists {
			continue
		}
		output = append(output, s)
	}
	return output
}

func (cfg *Config) filterDisabledIdentityProviders(arr []string) []string {
	var output []string
	if len(arr) == 0 || cfg.disabledIdentityProviders == nil {
		return arr
	}
	for _, s := range arr {
		if _, exists := cfg.disabledIdentityProviders[s]; exists {
			continue
		}
		output = append(output, s)
	}
	return output
}

// AddUserRegistry adds a user registry configuration.
func (cfg *Config) AddUserRegistry(r *registry.UserRegistryConfig) error {
	if err := r.Validate(); err != nil {
		return err
	}
	cfg.UserRegistries = append(cfg.UserRegistries, r)
	return nil
}
