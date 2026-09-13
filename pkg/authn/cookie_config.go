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

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

// ConfigureCookies replaces cookie configuration with a validated snapshot.
// Apply a complete configuration during assembly, before constructing a portal.
// Nil or invalid input leaves the portal unchanged. Feature-specific cookie
// scope checks and token-refresh name overrides remain in portal construction.
func (cfg *PortalConfig) ConfigureCookies(config *cookie.Config) error {
	if cfg == nil {
		return fmt.Errorf("portal config is nil")
	}
	if config == nil {
		return fmt.Errorf("cookie config is nil")
	}
	next := config.Clone()
	if err := next.Validate(); err != nil {
		return err
	}
	cfg.CookieConfig = next
	cfg.validated = false
	return nil
}
