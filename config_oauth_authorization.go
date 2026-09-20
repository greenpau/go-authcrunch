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
	"strings"
)

// Resolve policy references before provider discovery does network work. Distinct
// policies must not shadow each other's endpoints or overwrite browser cookies.
func (cfg *Config) validateOAuthAuthorizationPolicies() error {
	cookies := make(map[string]bool)
	var paths []string
	for _, policy := range cfg.AuthorizationPolicies {
		if policy == nil {
			return fmt.Errorf("authorization policy is nil")
		}
		if policy.OAuth == nil {
			continue
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		name := policy.OAuth.IdentityProvider
		if _, disabled := cfg.disabledIdentityProviders[name]; disabled {
			return fmt.Errorf("OAuth policy references a disabled identity provider")
		}
		found := false
		for _, provider := range cfg.IdentityProviders {
			if provider == nil || provider.Name != name {
				continue
			}
			if found || provider.Kind != "oauth" {
				return fmt.Errorf("OAuth policy requires one unambiguous OAuth identity provider")
			}
			found = true
		}
		if !found {
			return fmt.Errorf("OAuth policy identity provider not found")
		}
		for _, name := range []string{policy.OAuth.SessionCookieName, policy.OAuth.LoginCookieName} {
			if cookies[name] {
				return fmt.Errorf("OAuth policies must use distinct cookie names")
			}
			cookies[name] = true
		}
		base := policy.OAuth.BasePath
		for _, previous := range paths {
			if base == previous || strings.HasPrefix(base, previous+"/") || strings.HasPrefix(previous, base+"/") {
				return fmt.Errorf("OAuth policy endpoint paths overlap")
			}
		}
		paths = append(paths, base)
	}
	return nil
}
