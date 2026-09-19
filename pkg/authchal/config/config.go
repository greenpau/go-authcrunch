// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

// Package config owns typed authentication challenge policy independently of its parser.
package config

import (
	"encoding/json"
	"fmt"
	"slices"
)

const (
	// PasswordKeyword identifies a password challenge.
	PasswordKeyword = "password"
	// TotpKeyword identifies a time-based one-time password challenge.
	TotpKeyword = "totp"
	// U2fKeyword identifies a WebAuthn challenge.
	U2fKeyword = "u2f"
	// MfaKeyword identifies a generic MFA challenge.
	MfaKeyword = "mfa"
	// EmailKeyword identifies an email challenge.
	EmailKeyword = "email"
)

// Rule selects a sequence, or the first available alternative when HasOr is set.
// Conditions require every named method to be unavailable.
type Rule struct {
	Challenges []string `json:"challenges,omitempty" xml:"challenges,omitempty" yaml:"challenges,omitempty"`
	Conditions []string `json:"conditions,omitempty" xml:"conditions,omitempty" yaml:"conditions,omitempty"`
	HasOr      bool     `json:"has_or,omitempty" xml:"has_or,omitempty" yaml:"has_or,omitempty"`
}

// AuthenticationChallengeConfig is an ordered first-match policy. Statements
// retain the encoded source for compatibility; Rules are authoritative at runtime.
type AuthenticationChallengeConfig struct {
	Rules      []*Rule  `json:"rules,omitempty" xml:"rules,omitempty" yaml:"rules,omitempty"`
	Statements []string `json:"statements,omitempty" xml:"statements,omitempty" yaml:"statements,omitempty"`
}

// Validate checks typed policies without decoding directives or mutating inputs.
func (c *AuthenticationChallengeConfig) Validate() error {
	if c == nil || len(c.Rules) == 0 {
		return fmt.Errorf("no auth challenge rule statements found")
	}
	for _, r := range c.Rules {
		if r == nil || len(r.Challenges) == 0 {
			return fmt.Errorf("no challenge types specified")
		}
		if r.HasOr && len(r.Challenges) < 2 {
			return fmt.Errorf("challenge alternatives require multiple methods")
		}
		seen := map[string]bool{}
		for _, ch := range r.Challenges {
			if !validType(ch) {
				return fmt.Errorf("unsupported challenge type")
			}
			if seen[ch] {
				return fmt.Errorf("duplicate challenge type")
			}
			seen[ch] = true
		}
		conditions := map[string]bool{}
		for _, ch := range r.Conditions {
			if !validType(ch) {
				return fmt.Errorf("unsupported condition type")
			}
			if seen[ch] || conditions[ch] {
				return fmt.Errorf("conflicting or duplicate condition type")
			}
			conditions[ch] = true
		}
	}
	return nil
}

func validType(s string) bool {
	switch s {
	case PasswordKeyword, TotpKeyword, U2fKeyword, MfaKeyword, EmailKeyword:
		return true
	}
	return false
}

// Clone returns an independent policy snapshot.
func (c *AuthenticationChallengeConfig) Clone() *AuthenticationChallengeConfig {
	if c == nil {
		return nil
	}
	out := &AuthenticationChallengeConfig{Statements: slices.Clone(c.Statements)}
	for _, r := range c.Rules {
		if r == nil {
			out.Rules = append(out.Rules, nil)
			continue
		}
		out.Rules = append(out.Rules, &Rule{Challenges: slices.Clone(r.Challenges), Conditions: slices.Clone(r.Conditions), HasOr: r.HasOr})
	}
	return out
}

// Dump returns the JSON representation of the policy.
func (c *AuthenticationChallengeConfig) Dump() string {
	if c == nil {
		return "{}"
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return string(data)
}
