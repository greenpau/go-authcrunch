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
	"context"
	"fmt"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

func (cfg *Config) validateExternalRefreshStores() error {
	descriptors := map[string]*tokenrefresh.ExternalStoreConfig{}
	for _, descriptor := range cfg.ExternalRefreshStores {
		if err := descriptor.Validate(); err != nil {
			return err
		}
		if descriptors[descriptor.Name] != nil {
			return fmt.Errorf("duplicate managed refresh store declaration")
		}
		descriptors[descriptor.Name] = descriptor
	}
	for _, portal := range cfg.AuthenticationPortals {
		if portal == nil {
			return fmt.Errorf("portal configuration is nil")
		}
		c := portal.RefreshTokens
		if c == nil || c.Store == "" {
			continue
		}
		if err := c.Validate(); err != nil {
			return err
		}
		descriptor := descriptors[c.Store]
		if !c.Enabled || descriptor == nil {
			return fmt.Errorf("refresh requires an enabled declared store selection")
		}
		if cfg.State == nil {
			return fmt.Errorf("selected refresh storage requires persistent root state")
		}
		if c.MaxSessions != descriptor.MaxSessions || c.MaxRotations != descriptor.MaxRotations {
			return fmt.Errorf("portal refresh limits must match its managed store")
		}
	}
	return nil
}

func prepareExternalRefreshStores(config *Config, runtimes map[string]tokenrefresh.ManagedStore) (map[string]*tokenrefresh.ExternalStoreBinding, error) {
	bindings := map[string]*tokenrefresh.ExternalStoreBinding{}
	for _, descriptor := range config.ExternalRefreshStores {
		runtime, ok := runtimes[descriptor.Name]
		if !ok {
			return nil, fmt.Errorf("declared refresh store runtime is missing")
		}
		binding, err := (&tokenrefresh.ExternalStoreBinding{Config: descriptor, Store: runtime}).Prepare(context.Background())
		if err != nil {
			return nil, err
		}
		bindings[descriptor.Name] = binding
	}
	if len(bindings) != len(runtimes) {
		return nil, fmt.Errorf("refresh store runtime has no declaration")
	}
	return bindings, nil
}
