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

// Package external enforces additional decisions for authenticated requests.
package external

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Config binds a decision service to a trusted identity domain and policy.
// Attributes are literal top-level authenticated claim names, never headers.
// Omitted attributes disclose no claims beyond the identity binding.
type Config struct {
	Policy       string   `json:"policy,omitempty" xml:"policy,omitempty" yaml:"policy,omitempty"`
	Version      string   `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	Issuer       string   `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Realm        string   `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	SubjectClaim string   `json:"subject_claim,omitempty" xml:"subject_claim,omitempty" yaml:"subject_claim,omitempty"`
	TenantClaim  string   `json:"tenant_claim,omitempty" xml:"tenant_claim,omitempty" yaml:"tenant_claim,omitempty"`
	Attributes   []string `json:"attributes,omitempty" xml:"attributes,omitempty" yaml:"attributes,omitempty"`
	Timeout      string   `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// Validate applies defaults without contacting a backend.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("external authorization config is required")
	}
	if c.SubjectClaim == "" {
		c.SubjectClaim = "sub"
	}
	for _, s := range []string{c.Policy, c.Version, c.Issuer, c.Realm, c.SubjectClaim} {
		if !validText(s, 1024) {
			return fmt.Errorf("external authorization binding is invalid")
		}
	}
	if c.TenantClaim != "" && (!validText(c.TenantClaim, 1024) || c.TenantClaim == c.SubjectClaim) {
		return fmt.Errorf("external authorization tenant claim is invalid")
	}
	if len(c.Attributes) > 16 {
		return fmt.Errorf("external authorization accepts at most 16 attributes")
	}
	seen := make(map[string]bool)
	for _, name := range c.Attributes {
		if !validText(name, 1024) || seen[name] {
			return fmt.Errorf("external authorization attribute is invalid or duplicated")
		}
		seen[name] = true
	}
	if c.Timeout == "" {
		c.Timeout = "1s"
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil || d < time.Millisecond || d > 30*time.Second {
		return fmt.Errorf("external authorization timeout must be within 1ms-30s")
	}
	return nil
}

func validText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
