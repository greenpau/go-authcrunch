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

import "fmt"

// AdminAPIConfig configures the portal's admin API independently of its profile
// API. The zero value disables both admin access and private-key export. Apply
// it with PortalConfig.ConfigureAdminAPI before constructing the portal.
type AdminAPIConfig struct {
	Enabled bool `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	// FetchPrivateKeysEnabled permits authenticated portal admins to export
	// private signing keys. It also requires Enabled and defaults to false.
	FetchPrivateKeysEnabled bool `json:"fetch_private_keys_enabled,omitempty" xml:"fetch_private_keys_enabled,omitempty" yaml:"fetch_private_keys_enabled,omitempty"`
}

// ConfigureAdminAPI replaces the portal's admin settings with a snapshot of
// admin, preserving independently configured profile access. It initializes API
// when absent and preserves the established flat APIConfig serialization fields.
// A zero-value admin config disables both settings; nil is an error and leaves
// the portal unchanged. Call this during configuration, before serving requests.
func (cfg *PortalConfig) ConfigureAdminAPI(admin *AdminAPIConfig) error {
	if cfg == nil {
		return fmt.Errorf("portal config is nil")
	}
	if admin == nil {
		return fmt.Errorf("admin API config is nil")
	}
	api := APIConfig{}
	if cfg.API != nil {
		api = *cfg.API
	}
	api.AdminEnabled = admin.Enabled
	api.AdminFetchPrivateKeysEnabled = admin.FetchPrivateKeysEnabled
	cfg.API = &api
	return nil
}
