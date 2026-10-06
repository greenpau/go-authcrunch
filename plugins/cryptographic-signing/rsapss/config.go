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

// Package rsapss signs approved access-token claims using a local RSA key and SHA-256.
package rsapss

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// TokenType distinguishes these access tokens from ID tokens and other JWT uses.
const TokenType = "authcrunch-access+jwt"

// Config selects a key version and the sole issuer/audience it may sign for.
// KeyFile names an unencrypted PKCS#8 or PKCS#1 RSA PEM file (2048–8192 bits). Private bytes are never
// stored in this configuration. Use a new KeyID when rotating key material.
type Config struct {
	KeyFile     string `json:"key_file,omitempty" xml:"key_file,omitempty" yaml:"key_file,omitempty"`
	KeyID       string `json:"key_id,omitempty" xml:"key_id,omitempty" yaml:"key_id,omitempty"`
	Algorithm   string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Issuer      string `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Audience    string `json:"audience,omitempty" xml:"audience,omitempty" yaml:"audience,omitempty"`
	MaxLifetime string `json:"max_lifetime,omitempty" xml:"max_lifetime,omitempty" yaml:"max_lifetime,omitempty"`
}

// Validate normalizes defaults without reading files. Errors contain no values.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("PS256 signing config is required")
	}
	if !validText(c.KeyFile, 4096) || !validText(c.Issuer, 2048) || !validText(c.Audience, 1024) {
		return fmt.Errorf("PS256 signing key file, issuer and audience are required")
	}
	if c.KeyID == "" || len(c.KeyID) > 128 || strings.ContainsFunc(c.KeyID, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.')
	}) {
		return fmt.Errorf("PS256 signing key ID is invalid")
	}
	if c.Algorithm == "" {
		c.Algorithm = "PS256"
	}
	if c.Algorithm != "PS256" {
		return fmt.Errorf("PS256 signing algorithm is unsupported")
	}
	if c.MaxLifetime == "" {
		c.MaxLifetime = "15m"
	}
	d, err := time.ParseDuration(c.MaxLifetime)
	if err != nil || d < time.Second || d > 24*time.Hour || d%time.Second != 0 {
		return fmt.Errorf("PS256 signing lifetime must be whole seconds within 1s-24h")
	}
	return nil
}

func validText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
