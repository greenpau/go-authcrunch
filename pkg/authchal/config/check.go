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

package config

import "slices"

// ResolveChallenges returns the challenge list from the first matching
// rule, or nil if no rules match.
func (rs *AuthenticationChallengeConfig) ResolveChallenges(registeredTypes map[string]bool) []string {
	if rs == nil {
		return nil
	}
	for _, r := range rs.Rules {
		if r == nil || len(r.Challenges) == 0 {
			continue
		}
		if !challengesAvailable(r, registeredTypes) {
			continue
		}
		if hasRegisteredCondition(r.Conditions, registeredTypes) {
			continue
		}
		if r.HasOr {
			for _, ch := range r.Challenges {
				if isTypeRegistered(ch, registeredTypes) {
					return []string{ch}
				}
			}
		}
		return slices.Clone(r.Challenges)
	}
	return nil
}

// challengesAvailable checks whether the user has the required
// challenge types registered based on the rule's or/and semantics.
func challengesAvailable(r *Rule, registeredTypes map[string]bool) bool {
	if r.HasOr {
		return hasAnyChallenges(r.Challenges, registeredTypes)
	}
	return hasAllChallenges(r.Challenges, registeredTypes)
}

// hasAllChallenges checks whether the user has all non-password
// challenge types registered.
func hasAllChallenges(challenges []string, registeredTypes map[string]bool) bool {
	for _, ch := range challenges {
		if ch == PasswordKeyword {
			continue
		}
		if !isTypeRegistered(ch, registeredTypes) {
			return false
		}
	}
	return true
}

// hasAnyChallenges checks whether the user has at least one
// challenge type registered (password is always available).
func hasAnyChallenges(challenges []string, registeredTypes map[string]bool) bool {
	for _, ch := range challenges {
		if isTypeRegistered(ch, registeredTypes) {
			return true
		}
	}
	return false
}

// isTypeRegistered checks whether a challenge type is registered.
// The mfa type is a logical union of totp, u2f, and email.
func isTypeRegistered(ch string, registeredTypes map[string]bool) bool {
	if ch == PasswordKeyword {
		return true
	}
	if ch == MfaKeyword {
		return registeredTypes[TotpKeyword] || registeredTypes[U2fKeyword] || registeredTypes[EmailKeyword]
	}
	return registeredTypes[ch]
}

// hasRegisteredCondition checks whether any condition type is
// registered, meaning the "not available" condition is not met.
func hasRegisteredCondition(conditions []string, registeredTypes map[string]bool) bool {
	for _, cond := range conditions {
		if isTypeRegistered(cond, registeredTypes) {
			return true
		}
	}
	return false
}
