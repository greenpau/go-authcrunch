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

package authn

import (
	"fmt"
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// OIDCProviderConfig configures the portal's reusable OpenID Provider.
type OIDCProviderConfig = oidc.Config

// OIDCClientConfig registers a relying party with the OpenID Provider.
type OIDCClientConfig = oidc.ClientConfig

// ConfigureOIDCProvider attaches a validated, independent provider configuration
// before portal construction. A second provider definition is rejected. If the
// portal was previously validated, its defaults are revalidated at construction.
// This changes configuration only, never a running portal. Calls must not race
// with other accesses to this PortalConfig.
func (cfg *PortalConfig) ConfigureOIDCProvider(provider *OIDCProviderConfig) error {
	if cfg == nil {
		return fmt.Errorf("portal config is nil")
	}
	if cfg.OIDCProvider != nil {
		return fmt.Errorf("oidc provider is already configured for portal")
	}
	if provider == nil {
		return fmt.Errorf("oidc provider config is nil")
	}
	candidate := *provider
	candidate.Realms = slices.Clone(provider.Realms)
	candidate.SigningKeyFiles = slices.Clone(provider.SigningKeyFiles)
	candidate.Clients = nil
	for _, client := range provider.Clients {
		if err := candidate.AddClient(client); err != nil {
			return err
		}
	}
	if err := validateOIDCPortalConfig(&candidate); err != nil {
		return err
	}
	cfg.OIDCProvider = &candidate
	cfg.validated = false
	return nil
}
