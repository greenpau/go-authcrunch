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

package cookie

import (
	"fmt"
	"net/http"
	"strings"
)

type cookieName struct {
	suffix string
	value  *string
}

// Keep the complete set of cookie roles together for defaults and prefix changes.
func (c *Config) names() []cookieName {
	return []cookieName{
		{DefaultSessionIDCookieName, &c.SessionIDCookieName},
		{DefaultRefererCookieName, &c.RefererCookieName},
		{DefaultSandboxIDCookieName, &c.SandboxIDCookieName},
		{DefaultIdentityTokenCookieName, &c.IdentityTokenCookieName},
		{DefaultAccessTokenCookieName, &c.AccessTokenCookieName},
		{DefaultRefreshTokenCookieName, &c.RefreshTokenCookieName},
		{DefaultOIDCSessionIDCookieName, &c.OIDCSessionIDCookieName},
		{DefaultOIDCRequestIDCookieName, &c.OIDCRequestIDCookieName},
		{DefaultSAMLSessionIDCookieName, &c.SAMLSessionIDCookieName},
	}
}

// SetCookieNamePrefix changes all omitted or previously defaulted names,
// including both OIDC roles, preserving names that differ from the old prefix
// plus their role suffix. An empty prefix resets to AUTHP. An explicit name that
// equals an old default is indistinguishable from that default: apply such an
// override after changing the prefix. Directive parsing handles this ordering.
// Invalid names or collisions leave c unchanged. Call before runtime creation.
func (c *Config) SetCookieNamePrefix(prefix string) error {
	if c == nil {
		return fmt.Errorf("cookie config is nil")
	}
	old := c.CookieNamePrefix
	if old == "" {
		old = DefaultCookieNamePrefix
	}
	if prefix == "" {
		prefix = DefaultCookieNamePrefix
	}
	next := *c
	next.CookieNamePrefix = prefix
	for _, entry := range next.names() {
		if *entry.value == "" || *entry.value == old+"_"+entry.suffix {
			*entry.value = prefix + "_" + entry.suffix
		}
	}
	if err := next.validateNames(); err != nil {
		return err
	}
	*c = next
	return nil
}

// Clone returns independent cookie configuration, including domain settings.
// A nil receiver returns nil. No validation or defaults are applied.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	cloned := *c
	if c.Domains != nil {
		cloned.Domains = make(map[string]*DomainConfig, len(c.Domains))
		for key, domain := range c.Domains {
			if domain == nil {
				cloned.Domains[key] = nil
				continue
			}
			copy := *domain
			cloned.Domains[key] = &copy
		}
	}
	return &cloned
}

// Validate applies defaults and validates names, collisions, paths, domains,
// SameSite attributes, and reserved prefixes. Lifetimes and feature-specific
// scope/security requirements remain with the issuing runtime. Explicit names need not start
// with AUTHP. Validation does not create a factory or start a runtime.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("cookie config is nil")
	}
	c.ApplyDefaults()
	if err := c.validateNames(); err != nil {
		return err
	}
	if err := normalizeSameSite(&c.SameSite); err != nil {
		return err
	}
	if err := (&http.Cookie{Name: c.AccessTokenCookieName, Path: c.Path}).Valid(); err != nil {
		return fmt.Errorf("invalid cookie path")
	}
	seen := make(map[string]bool)
	for key, domain := range c.Domains {
		if domain == nil {
			return fmt.Errorf("cookie domain config is nil")
		}
		key = strings.TrimPrefix(key, ".")
		if key == "" || (&http.Cookie{Name: c.AccessTokenCookieName, Domain: key}).Valid() != nil {
			return fmt.Errorf("invalid cookie domain")
		}
		if seen[key] {
			return fmt.Errorf("duplicate cookie domain")
		}
		seen[key] = true
		if (&http.Cookie{Name: c.AccessTokenCookieName, Domain: domain.Domain, Path: domain.Path}).Valid() != nil {
			return fmt.Errorf("invalid cookie domain attributes")
		}
		if err := normalizeSameSite(&domain.SameSite); err != nil {
			return err
		}
	}
	return c.validatePrefixes()
}

func (c *Config) validateNames() error {
	if (&http.Cookie{Name: c.CookieNamePrefix + "_" + DefaultSessionIDCookieName}).Valid() != nil {
		return fmt.Errorf("invalid cookie name prefix")
	}
	seen := make(map[string]bool)
	for _, entry := range c.names() {
		if (&http.Cookie{Name: *entry.value}).Valid() != nil {
			return fmt.Errorf("invalid cookie name for %s", entry.suffix)
		}
		if seen[*entry.value] {
			return fmt.Errorf("duplicate cookie name for %s", entry.suffix)
		}
		seen[*entry.value] = true
	}
	return nil
}

func normalizeSameSite(value *string) error {
	switch strings.ToLower(*value) {
	case "":
	case "lax":
		*value = "Lax"
	case "strict":
		*value = "Strict"
	case "none":
		*value = "None"
	default:
		return fmt.Errorf("the SameSite cookie attribute %q is invalid", *value)
	}
	return nil
}
