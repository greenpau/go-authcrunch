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

// ValidatePrefix checks browser-reserved cookie prefixes against effective
// attributes. Prefix matching is case-insensitive, as required by RFC6265bis.
// Ordinary cookie names impose no extra attribute requirements.
func ValidatePrefix(name, domain, path string, secure bool) error {
	lower := strings.ToLower(name)
	host := strings.HasPrefix(lower, "__host-")
	if (host || strings.HasPrefix(lower, "__secure-")) && !secure {
		return fmt.Errorf("reserved cookie prefix requires Secure")
	}
	if host && (domain != "" || path != "/") {
		return fmt.Errorf("__Host- cookies require Path=/ and no Domain")
	}
	return nil
}

func portalCookiePath(basePath string) string {
	path := strings.TrimSuffix(basePath, "/")
	if path == "" {
		return "/"
	}
	return path
}

// ValidatePortalPath checks cookies whose path is determined by the portal's
// HTTP mount. Config.Validate already checks their security attributes.
// Embedders must call it before serving a dynamically mounted portal.
func (f *Factory) ValidatePortalPath(basePath string) error {
	for _, name := range []string{f.RefererCookieName, f.SandboxIDCookieName} {
		if err := ValidatePrefix(name, "", portalCookiePath(basePath), true); err != nil {
			return fmt.Errorf("portal cookie path: %w", err)
		}
	}
	return nil
}

// ValidateIdentityTokenCookieName checks a provider-owned name without changing
// it. Identity cookies use a whoami subpath, so __Host- names are incompatible.
func (f *Factory) ValidateIdentityTokenCookieName(name string) error {
	if name == "" {
		return nil // The provider does not issue an identity cookie.
	}
	if (&http.Cookie{Name: name}).Valid() != nil {
		return fmt.Errorf("invalid identity cookie name")
	}
	return ValidatePrefix(name, "", "/whoami", !f.config.Insecure)
}

func (c *Config) validatePrefixes() error {
	path := c.Path
	if path == "" {
		path = "/"
	}
	// Validate the fallback, including requests that do not select a domain.
	domain := ""
	if c.GuessDomainEnabled && !c.StripDomainEnabled {
		domain = "guessed.example"
	}
	if err := c.validateHostPrefixes(domain, path, !c.Insecure); err != nil {
		return err
	}
	for _, entry := range c.Domains {
		domain, effectivePath := entry.Domain, path
		if entry.StripDomainEnabled {
			domain = ""
		}
		if entry.Path != "" {
			effectivePath = entry.Path
		}
		// Match the legacy issuance rule: either secure setting keeps Secure on.
		if err := c.validateHostPrefixes(domain, effectivePath, !entry.Insecure || !c.Insecure); err != nil {
			return err
		}
	}
	for _, name := range []string{c.RefererCookieName, c.SandboxIDCookieName, c.IdentityTokenCookieName} {
		path := "/"
		if name == c.IdentityTokenCookieName {
			path = "/whoami"
		}
		if err := ValidatePrefix(name, "", path, !c.Insecure); err != nil {
			return err
		}
	}
	if err := ValidatePrefix(c.SAMLSessionIDCookieName, "", "/", true); err != nil {
		return fmt.Errorf("SAML session cookie: %w", err)
	}
	// Active refresh and OIDC runtimes own their stricter security and mount
	// checks. Their names must not inherit legacy refresh-path restrictions.
	return nil
}

func (c *Config) validateHostPrefixes(domain, path string, secure bool) error {
	if err := ValidatePrefix(c.AccessTokenCookieName, domain, path, secure); err != nil {
		return fmt.Errorf("access cookie: %w", err)
	}
	if err := ValidatePrefix(c.SessionIDCookieName, domain, "/", secure); err != nil {
		return fmt.Errorf("session cookie: %w", err)
	}
	return nil
}
