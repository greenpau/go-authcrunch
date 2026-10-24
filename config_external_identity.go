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

	"github.com/greenpau/go-authcrunch/pkg/ids"
)

func (cfg *Config) validateExternalIdentityStores() (map[string]*ids.ExternalIdentityStoreConfig, error) {
	external := make(map[string]*ids.ExternalIdentityStoreConfig, len(cfg.ExternalIdentityStores))
	names := make(map[string]bool)
	for _, store := range cfg.IdentityStores {
		if store == nil {
			return nil, fmt.Errorf("identity store configuration is nil")
		}
		names[store.Name] = true
	}
	for _, store := range cfg.ExternalIdentityStores {
		if err := store.Validate(); err != nil {
			return nil, err
		}
		if names[store.Name] {
			return nil, fmt.Errorf("duplicate external identity store name %q", store.Name)
		}
		names[store.Name] = true
		external[store.Name] = store
	}
	return external, nil
}

func validateExternalIdentityStoreBindings(config *Config, bindings map[string]ids.IdentityStore) error {
	expected := make(map[string]bool, len(config.ExternalIdentityStores))
	for _, descriptor := range config.ExternalIdentityStores {
		expected[descriptor.Name] = true
		store, found := bindings[descriptor.Name]
		if !found {
			return fmt.Errorf("external identity store %q runtime binding is missing", descriptor.Name)
		}
		if err := validateExternalIdentityStoreBinding(descriptor, store); err != nil {
			return err
		}
	}
	for name := range bindings {
		if !expected[name] {
			return fmt.Errorf("external identity store %q has no descriptor", name)
		}
	}
	return nil
}

// Contain only plugin metadata/readiness checks at this constructor boundary. An interface
// can contain a typed nil pointer; calling its methods must not panic the host.
// Configuration, attachment binding, runtime construction and HTTP requests
// remain outside recovery; optional attachment checks only inspect existing wiring.
func validateExternalIdentityStoreBinding(descriptor *ids.ExternalIdentityStoreConfig, store ids.IdentityStore) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("external identity store %q has an invalid runtime binding", descriptor.Name)
		}
	}()
	if store == nil || !store.Configured() {
		return fmt.Errorf("external identity store %q is not configured", descriptor.Name)
	}
	if store.GetName() != descriptor.Name || store.GetKind() != descriptor.Kind || store.GetRealm() != descriptor.Realm {
		return fmt.Errorf("external identity store %q runtime identifiers do not match", descriptor.Name)
	}
	if err := validateBorrowedIdentityAttachment(store); err != nil {
		return fmt.Errorf("external identity store %q attachment is not ready", descriptor.Name)
	}
	return nil
}
