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
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
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

// Capture the immutable attachment once during plugin metadata preflight. Later
// wiring uses this pointer and the root's actual local store, without invoking
// another plugin accessor after acquiring root resources.
type identityProviderAttachmentBinding struct {
	providerName string
	storeName    string
	attachment   *attachment.Attachment
}

func validateExternalIdentityProviderBindings(config *Config, bindings map[string]idp.IdentityProvider, targets map[string]string) ([]identityProviderAttachmentBinding, error) {
	expected := make(map[string]bool, len(config.ExternalIdentityProviders))
	var prepared []identityProviderAttachmentBinding
	for _, descriptor := range config.ExternalIdentityProviders {
		expected[descriptor.Name] = true
		provider, found := bindings[descriptor.Name]
		if !found {
			return nil, fmt.Errorf("external identity provider %q runtime binding is missing", descriptor.Name)
		}
		target, bind := targets[descriptor.Name]
		if bind {
			if err := validateIdentityProviderAttachmentTarget(config, target); err != nil {
				return nil, fmt.Errorf("external identity provider %q requires a unique enabled root-owned local attachment store", descriptor.Name)
			}
		}
		attached, err := validateExternalIdentityProviderBinding(descriptor, provider, target, bind)
		if err != nil {
			return nil, err
		}
		if bind {
			prepared = append(prepared, identityProviderAttachmentBinding{providerName: descriptor.Name, storeName: target, attachment: attached})
		}
	}
	for name := range bindings {
		if !expected[name] {
			return nil, fmt.Errorf("external identity provider %q has no descriptor", name)
		}
	}
	for name := range targets {
		if !expected[name] {
			return nil, fmt.Errorf("external identity provider attachment %q has no descriptor", name)
		}
	}
	return prepared, nil
}

// This reference check runs before state or stores open. An external store
// cannot impersonate the built-in local kind; opted targets are root-owned.
func validateIdentityProviderAttachmentTarget(config *Config, target string) error {
	if target == "" || (attachment.Config{LocalIdentityStore: target}).Validate() != nil {
		return fmt.Errorf("invalid local attachment store name")
	}
	if _, disabled := config.disabledIdentityStores[target]; disabled {
		return fmt.Errorf("local attachment store is disabled")
	}
	var matches int
	for _, store := range config.IdentityStores {
		if store.Name != target {
			continue
		}
		if store.Kind != "local" {
			return fmt.Errorf("attachment store is not local")
		}
		matches++
	}
	if matches != 1 {
		return fmt.Errorf("attachment store is not unique")
	}
	return nil
}

// Contain only plugin metadata/readiness checks at this constructor boundary,
// including typed nil interfaces. Configure, attachment binding, construction
// and request handling are deliberately outside this recovery scope.
func validateExternalIdentityProviderBinding(descriptor *idp.ExternalIdentityProviderConfig, provider idp.IdentityProvider, target string, bind bool) (attached *attachment.Attachment, err error) {
	defer func() {
		if recover() != nil {
			attached = nil
			err = fmt.Errorf("external identity provider %q has an invalid runtime binding", descriptor.Name)
		}
	}()
	if provider == nil || provider.GetName() != descriptor.Name || provider.GetKind() != descriptor.Kind || provider.GetDriver() != descriptor.Driver || provider.GetRealm() != descriptor.Realm {
		return nil, fmt.Errorf("external identity provider %q runtime identifiers do not match", descriptor.Name)
	}
	if !provider.Configured() {
		return nil, fmt.Errorf("external identity provider %q is not configured", descriptor.Name)
	}
	if bind {
		consumer, ok := provider.(attachment.Consumer)
		if !ok {
			return nil, fmt.Errorf("external identity provider %q has no identity attachment", descriptor.Name)
		}
		attached = consumer.IdentityAttachment()
		if attached == nil || attached.StoreName() != target {
			return nil, fmt.Errorf("external identity provider %q attachment does not match its target", descriptor.Name)
		}
		// A root-created local store cannot be the provider's existing pointer.
		// Refuse reuse before Configure can touch the candidate's account files.
		// Store on this nonempty explicit name inspects wiring without I/O.
		if _, err := attached.Store(); err == nil {
			return nil, fmt.Errorf("external identity provider %q attachment is already bound", descriptor.Name)
		}
		return attached, nil
	}
	if err := validateBorrowedIdentityAttachment(provider); err != nil {
		return nil, fmt.Errorf("external identity provider %q attachment is not ready", descriptor.Name)
	}
	return nil, nil
}

func (srv *Server) bindExternalIdentityProviderAttachments(bindings []identityProviderAttachmentBinding) error {
	for _, binding := range bindings {
		store, ok := srv.nameRefs.identityStores[binding.storeName].(*local.IdentityStore)
		if !ok || store == nil || !store.Configured() {
			return fmt.Errorf("external identity provider %q attachment target is unavailable", binding.providerName)
		}
		if err := attachment.BindStore(binding.attachment, store); err != nil {
			return fmt.Errorf("external identity provider %q attachment binding failed", binding.providerName)
		}
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
