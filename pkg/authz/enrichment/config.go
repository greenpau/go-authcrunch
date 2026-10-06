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

// Package enrichment provides request-time claims enrichment for authorization.
// It never authenticates identities or modifies signed tokens.
package enrichment

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Namespace is reserved for request-local attributes from the selected backend.
const Namespace = "enrichment."

// AttributeConfig declares an allowed, literal custom claim and its type.
type AttributeConfig struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Type string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// Config binds a trusted backend to authenticated claim sources and an audience.
// SubjectClaim must identify an immutable account within issuer, realm and
// tenant; the host must establish that guarantee at the identity source.
type Config struct {
	Source       string            `json:"source,omitempty" xml:"source,omitempty" yaml:"source,omitempty"`
	Version      string            `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	Issuer       string            `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Realm        string            `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	SubjectClaim string            `json:"subject_claim,omitempty" xml:"subject_claim,omitempty" yaml:"subject_claim,omitempty"`
	TenantClaim  string            `json:"tenant_claim,omitempty" xml:"tenant_claim,omitempty" yaml:"tenant_claim,omitempty"`
	Audience     string            `json:"audience,omitempty" xml:"audience,omitempty" yaml:"audience,omitempty"`
	Timeout      string            `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
	MaxAge       string            `json:"max_age,omitempty" xml:"max_age,omitempty" yaml:"max_age,omitempty"`
	Attributes   []AttributeConfig `json:"attributes,omitempty" xml:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Validate checks the claim name and type. Standard identity, token, provider and
// authentication claims cannot be supplied by an enrichment backend.
func (a AttributeConfig) Validate() error {
	if !validText(a.Name, 256) || a.Name == Namespace || (a.Type != "string" && a.Type != "string_list" && a.Type != "json") {
		return fmt.Errorf("claims enrichment attribute declaration is invalid")
	}
	if strings.HasPrefix(a.Name, Namespace) {
		return nil
	}
	switch a.Name {
	case "aud", "exp", "jti", "iat", "iss", "nbf", "sub", "subject", "id",
		"name", "email", "mail", "roles", "role", "groups", "group", "amr",
		"scopes", "scope", "org", "addr", "origin", "realm", "picture", "metadata",
		"app_metadata", "realm_access", "paths", "acl", "frontend_links", "challenges", "auth_methods",
		"auth_time", "acr", "azp", "sid", "nonce", "at_hash", "c_hash", "s_hash", "cnf":
		return fmt.Errorf("claims enrichment attribute name is protected")
	}
	if strings.HasPrefix(a.Name, "github_") || strings.HasPrefix(a.Name, "authcrunch_") {
		return fmt.Errorf("claims enrichment attribute name is protected")
	}
	return nil
}

// Validate normalizes defaults and rejects incomplete or unsafe bindings.
// Errors never include supplied values. Validation performs no IO.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("claims enrichment config is required")
	}
	for _, value := range []string{c.Source, c.Version, c.Issuer, c.Realm, c.SubjectClaim, c.TenantClaim, c.Audience} {
		if !validText(value, 1024) {
			return fmt.Errorf("claims enrichment binding is invalid")
		}
	}
	for _, key := range []string{c.SubjectClaim, c.TenantClaim} {
		if strings.HasPrefix(key, Namespace) {
			return fmt.Errorf("claims enrichment identity cannot depend on enrichment")
		}
	}
	if c.SubjectClaim == c.TenantClaim {
		return fmt.Errorf("claims enrichment identity bindings must differ")
	}
	if c.Timeout == "" {
		c.Timeout = "1s"
	}
	if c.MaxAge == "" {
		c.MaxAge = "1m"
	}
	for _, entry := range []struct {
		value string
		max   time.Duration
	}{{c.Timeout, 30 * time.Second}, {c.MaxAge, 24 * time.Hour}} {
		d, err := time.ParseDuration(entry.value)
		if err != nil || d <= 0 || d > entry.max {
			return fmt.Errorf("claims enrichment duration is invalid")
		}
	}
	if len(c.Attributes) == 0 || len(c.Attributes) > 32 {
		return fmt.Errorf("claims enrichment requires 1-32 attributes")
	}
	seen := make(map[string]bool)
	for _, a := range c.Attributes {
		if err := a.Validate(); err != nil {
			return err
		}
		if seen[a.Name] || a.Name == c.SubjectClaim || a.Name == c.TenantClaim {
			return fmt.Errorf("claims enrichment attribute declaration is invalid")
		}
		seen[a.Name] = true
	}
	return nil
}

func validText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
