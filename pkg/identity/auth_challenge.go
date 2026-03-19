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

package identity

import (
	"fmt"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// AuthChallengeRule represents a single authentication challenge
// rule with optional fallback conditions.
//
//	auth challenges u2f
//	auth challenges password totp if u2f not available
//	auth challenges password if u2f and totp not available
type AuthChallengeRule struct {
	Challenges []string `json:"challenges,omitempty" xml:"challenges,omitempty" yaml:"challenges,omitempty"`
	Conditions []string `json:"conditions,omitempty" xml:"conditions,omitempty" yaml:"conditions,omitempty"`
}

var validChallengeTypes = map[string]bool{
	"password": true,
	"totp":     true,
	"u2f":      true,
}

// ParseAuthChallengeRule parses a directive string into an
// AuthChallengeRule. The input format is:
//
//	<challenge> [<challenge> ...] [if <type> [and <type> ...] not available]
func ParseAuthChallengeRule(s string) (*AuthChallengeRule, error) {
	args, err := cfgutil.DecodeArgs(s)
	if err != nil {
		return nil, fmt.Errorf("auth challenge rule: %v", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty auth challenge rule")
	}

	rule := &AuthChallengeRule{}
	seen := make(map[string]bool)
	i := 0

	// Collect challenge types until "if" or end of args.
	for i < len(args) && args[i] != "if" {
		ch := args[i]
		if !validChallengeTypes[ch] {
			return nil, fmt.Errorf("unsupported challenge type: %s", ch)
		}
		if seen[ch] {
			return nil, fmt.Errorf("duplicate challenge type: %s", ch)
		}
		seen[ch] = true
		rule.Challenges = append(rule.Challenges, ch)
		i++
	}
	if len(rule.Challenges) == 0 {
		return nil, fmt.Errorf("no challenge types specified")
	}

	if i >= len(args) {
		return rule, nil
	}

	// Skip "if", parse condition types, skip "and" and "not available".
	i++ // skip "if"
	for i < len(args) {
		tok := args[i]
		if tok == "and" || tok == "not" || tok == "available" {
			i++
			continue
		}
		if !validChallengeTypes[tok] {
			return nil, fmt.Errorf("unsupported condition type: %s", tok)
		}
		if seen[tok] {
			return nil, fmt.Errorf("condition type %s conflicts with challenge type", tok)
		}
		rule.Conditions = append(rule.Conditions, tok)
		i++
	}
	if len(rule.Conditions) == 0 {
		return nil, fmt.Errorf("empty condition in auth challenge rule")
	}

	return rule, nil
}

// hasMfaChallenges checks whether the user has all non-password
// challenge types registered.
func hasMfaChallenges(challenges []string, registeredTypes map[string]bool) bool {
	for _, ch := range challenges {
		if ch == "password" {
			continue
		}
		if !registeredTypes[ch] {
			return false
		}
	}
	return true
}

// evaluateAuthChallengeRules returns the challenge list from the
// first matching rule, or nil if no rules match (caller should
// fall back to default challenge detection).
func evaluateAuthChallengeRules(rules []*AuthChallengeRule, registeredTypes map[string]bool) []string {
	for _, rule := range rules {
		if rule == nil || len(rule.Challenges) == 0 {
			continue
		}

		if !hasMfaChallenges(rule.Challenges, registeredTypes) {
			continue
		}

		if len(rule.Conditions) == 0 {
			return rule.Challenges
		}

		// Check that all condition types are "not available".
		matched := true
		for _, cond := range rule.Conditions {
			if registeredTypes[cond] {
				matched = false
				break
			}
		}
		if matched {
			return rule.Challenges
		}
	}
	return nil
}
