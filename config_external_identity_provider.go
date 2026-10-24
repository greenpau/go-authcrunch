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

	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
)

// Index only declaration metadata. Neither provider configuration nor runtime
// readiness is consulted during pure root preflight.
func (cfg *Config) identityProviderRealms() (map[string]string, error) {
	realms := make(map[string]string, len(cfg.IdentityProviders)+len(cfg.ExternalIdentityProviders))
	add := func(name, realm string) error {
		if name == "" {
			return fmt.Errorf("identity provider identifiers are required")
		}
		if _, exists := realms[name]; exists {
			return fmt.Errorf("duplicate identity provider name %q", name)
		}
		realms[name] = realm
		return nil
	}
	for _, provider := range cfg.IdentityProviders {
		if provider == nil {
			return nil, fmt.Errorf("identity provider configuration is nil")
		}
		realm, _ := provider.Params["realm"].(string)
		if err := add(provider.Name, realm); err != nil {
			return nil, err
		}
	}
	for _, descriptor := range cfg.ExternalIdentityProviders {
		if err := descriptor.Validate(); err != nil {
			return nil, err
		}
		if err := add(descriptor.Name, descriptor.Realm); err != nil {
			return nil, err
		}
	}
	return realms, nil
}

func validateExternalIdentityProviderBindings(config *Config, bindings map[string]idp.IdentityProvider) error {
	expected := make(map[string]bool, len(config.ExternalIdentityProviders))
	for _, descriptor := range config.ExternalIdentityProviders {
		expected[descriptor.Name] = true
		provider, found := bindings[descriptor.Name]
		if !found {
			return fmt.Errorf("external identity provider %q runtime binding is missing", descriptor.Name)
		}
		if err := validateExternalIdentityProviderBinding(descriptor, provider); err != nil {
			return err
		}
	}
	for name := range bindings {
		if !expected[name] {
			return fmt.Errorf("external identity provider %q has no descriptor", name)
		}
	}
	return nil
}

// Contain only plugin metadata/readiness checks at this constructor boundary,
// including typed nil interfaces. Configure, attachment binding, construction
// and request handling are deliberately outside this recovery scope.
func validateExternalIdentityProviderBinding(descriptor *idp.ExternalIdentityProviderConfig, provider idp.IdentityProvider) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("external identity provider %q has an invalid runtime binding", descriptor.Name)
		}
	}()
	if provider == nil || provider.GetName() != descriptor.Name || provider.GetKind() != descriptor.Kind || provider.GetDriver() != descriptor.Driver || provider.GetRealm() != descriptor.Realm {
		return fmt.Errorf("external identity provider %q runtime identifiers do not match", descriptor.Name)
	}
	if !provider.Configured() {
		return fmt.Errorf("external identity provider %q is not configured", descriptor.Name)
	}
	if err := validateBorrowedIdentityAttachment(provider); err != nil {
		return fmt.Errorf("external identity provider %q attachment is not ready", descriptor.Name)
	}
	return nil
}

// Validate only existing optional attachment wiring. The unnamed private
// attachment remains lazy: calling Store there would allocate memory identity
// state. Explicit StoreName returns an existing binding or an error without I/O.
func validateBorrowedIdentityAttachment(backend any) error {
	consumer, ok := backend.(attachment.Consumer)
	if !ok {
		return nil
	}
	attached := consumer.IdentityAttachment()
	if attached == nil {
		return fmt.Errorf("identity attachment is missing")
	}
	if attached.StoreName() == "" {
		return nil
	}
	if _, err := attached.Store(); err != nil {
		return fmt.Errorf("identity attachment is not bound")
	}
	return nil
}
