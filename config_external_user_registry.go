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
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
)

// validateUserRegistries operates only on declarations. Runtime dependencies
// arrive later through ServerOptions and are never configured by this path.
func (cfg *Config) validateUserRegistries(externalStores map[string]*ids.ExternalIdentityStoreConfig) (map[string]string, map[string]string, error) {
	stores := make(map[string]string)
	for _, store := range cfg.IdentityStores {
		realm, _ := store.Params["realm"].(string)
		stores[store.Name] = realm
	}
	for name, store := range externalStores {
		stores[name] = store.Realm
	}
	byName, byStore, locals := make(map[string]string), make(map[string]string), make(map[string]string)
	add := func(name, store, realm string) error {
		if name == "" || store == "" {
			return fmt.Errorf("user registry identifiers are required")
		}
		if _, exists := byName[name]; exists {
			return fmt.Errorf("duplicate user registry name %q", name)
		}
		if _, exists := byStore[store]; exists {
			return fmt.Errorf("multiple user registries reference identity store %q", store)
		}
		expected, exists := stores[store]
		if !exists {
			return fmt.Errorf("identity store %q referenced in %q user registry not found", store, name)
		}
		if realm != "" && realm != expected {
			return fmt.Errorf("user registry %q realm does not match identity store", name)
		}
		byName[name], byStore[store] = store, name
		return nil
	}
	for _, provider := range cfg.UserRegistration.LocalProviders {
		if provider == nil {
			return nil, nil, fmt.Errorf("local user registry configuration is nil")
		}
		if _, external := externalStores[provider.IdentityStoreName]; external {
			return nil, nil, fmt.Errorf("local user registry cannot use an external identity store")
		}
		if err := add(provider.Name, provider.IdentityStoreName, provider.RealmName); err != nil {
			return nil, nil, err
		}
		// This is declarative local configuration; NewRuntime makes the owned copy.
		provider.SetRealmName(stores[provider.IdentityStoreName])
		if err := provider.SetCredentials(cfg.Credentials); err != nil {
			return nil, nil, err
		}
		if err := provider.SetMessaging(cfg.Messaging); err != nil {
			return nil, nil, err
		}
		locals[provider.IdentityStoreName] = provider.Name
	}
	for _, descriptor := range cfg.ExternalUserRegistries {
		if err := descriptor.Validate(); err != nil {
			return nil, nil, err
		}
		if err := add(descriptor.Name, descriptor.IdentityStore, descriptor.Realm); err != nil {
			return nil, nil, err
		}
	}
	return byName, locals, nil
}

func validatePortalUserRegistries(portal *authn.PortalConfig, byName, locals map[string]string) error {
	// Preserve local auto-enrollment selection; external providers require explicit
	// selection, including after native configuration round trips.
	if len(portal.UserRegistries) == 0 {
		for _, store := range portal.IdentityStores {
			if name, ok := locals[store]; ok && !slices.Contains(portal.UserRegistries, name) {
				portal.UserRegistries = append(portal.UserRegistries, name)
			}
		}
	}
	selected := make([]string, 0, len(portal.UserRegistries))
	for _, name := range portal.UserRegistries {
		store, ok := byName[name]
		if !ok {
			return fmt.Errorf("user registry %q configuration not found", name)
		}
		if !slices.Contains(portal.IdentityStores, store) {
			return fmt.Errorf("user registry %q identity store is not selected by portal", name)
		}
		if !slices.Contains(selected, name) {
			selected = append(selected, name)
		}
	}
	portal.UserRegistries = selected
	return nil
}

func validateExternalUserRegistryBindings(config *Config, bindings map[string]registry.Provider) error {
	expected := make(map[string]bool, len(config.ExternalUserRegistries))
	for _, descriptor := range config.ExternalUserRegistries {
		expected[descriptor.Name] = true
		provider, ok := bindings[descriptor.Name]
		if !ok {
			return fmt.Errorf("external user registry %q runtime binding is missing", descriptor.Name)
		}
		if err := validateExternalUserRegistryMetadata(descriptor, provider); err != nil {
			return err
		}
		if !config.Messaging.FindProvider(descriptor.EmailProvider) {
			return fmt.Errorf("external user registry %q messaging binding is missing", descriptor.Name)
		}
		if err := validateExternalUserRegistryReady(provider); err != nil {
			return fmt.Errorf("external user registry %q is not ready", descriptor.Name)
		}
	}
	for name := range bindings {
		if !expected[name] {
			return fmt.Errorf("external user registry %q has no descriptor", name)
		}
	}
	return nil
}

// Contain only metadata checks, including methods on typed nil interfaces.
// Readiness has its own narrow validation boundary below; constructors and
// request processing remain outside panic recovery.
func validateExternalUserRegistryMetadata(descriptor *registry.ExternalUserRegistryConfig, provider registry.Provider) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("external user registry %q has an invalid runtime binding", descriptor.Name)
		}
	}()
	if provider == nil || provider.GetName() != descriptor.Name || provider.Kind() != descriptor.Kind || provider.GetIdentityStoreName() != descriptor.IdentityStore || provider.GetRealmName() != descriptor.Realm || provider.GetEmailProvider() != descriptor.EmailProvider {
		return fmt.Errorf("external user registry %q runtime identifiers do not match", descriptor.Name)
	}
	return nil
}

// Contain only the plugin validation boundary. Root construction, mutation and
// request handling are not covered by panic recovery.
func validateExternalUserRegistryReady(provider registry.Provider) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid user registry runtime")
		}
	}()
	return provider.Validate()
}
