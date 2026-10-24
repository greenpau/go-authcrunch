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
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/kms"
)

func (cfg *Config) validateExternalAccessSigners() error {
	descriptors := map[string]*kms.ExternalAccessSignerConfig{}
	for _, descriptor := range cfg.ExternalAccessSigners {
		if err := descriptor.Validate(); err != nil {
			return err
		}
		if descriptors[descriptor.Name] != nil {
			return fmt.Errorf("duplicate access signer declaration")
		}
		descriptors[descriptor.Name] = descriptor
	}
	for _, portal := range cfg.AuthenticationPortals {
		if portal == nil {
			return fmt.Errorf("portal configuration is nil")
		}
		if portal.AccessSigner == "" {
			if portal.AccessTokenProfile != nil {
				return fmt.Errorf("portal access profile requires selected signing")
			}
			continue
		}
		descriptor := descriptors[portal.AccessSigner]
		profile := portal.AccessTokenProfile
		if descriptor == nil || profile == nil || profile.Validate() != nil {
			return fmt.Errorf("portal requires a declared access signer and profile")
		}
		if err := portal.Validate(); err != nil {
			return err
		}
		policy := descriptor.Policy
		if profile.Issuer != policy.Issuer || profile.Audience != policy.Audience || profile.MaxLifetimeSeconds != policy.MaxLifetimeSeconds || !slices.Contains(profile.KeyIDs, policy.KeyID) {
			return fmt.Errorf("portal signer profile does not match declaration")
		}
		if refresh := portal.RefreshTokens; refresh != nil && refresh.Enabled && policy.Issuer != refresh.PublicOrigin+strings.TrimSuffix(refresh.BasePath, "/") {
			return fmt.Errorf("renewable access signer issuer must match the portal origin and mount")
		}
	}
	for _, policy := range cfg.AuthorizationPolicies {
		if policy == nil {
			return fmt.Errorf("authorization policy is nil")
		}
		if policy.AccessTokenProfile != nil {
			if err := policy.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
func prepareExternalAccessSigners(config *Config, runtimes map[string]kms.AccessSigner) (map[string]*kms.AccessSignerBinding, error) {
	bindings := map[string]*kms.AccessSignerBinding{}
	for _, descriptor := range config.ExternalAccessSigners {
		runtime, ok := runtimes[descriptor.Name]
		if !ok {
			return nil, fmt.Errorf("declared access signer runtime is missing")
		}
		binding, err := (&kms.AccessSignerBinding{Config: descriptor, Signer: runtime}).Prepare()
		if err != nil {
			return nil, err
		}
		bindings[descriptor.Name] = binding
	}
	if len(bindings) != len(runtimes) {
		return nil, fmt.Errorf("access signer runtime has no declaration")
	}
	return bindings, nil
}
