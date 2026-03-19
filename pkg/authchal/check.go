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

package authchal

// ResolveChallenges returns the challenge list from the first matching
// rule, or nil if no rules match.
func (rs *Ruleset) ResolveChallenges(registeredTypes map[string]bool) []string {
	for _, r := range rs.Rules {
		if r == nil || len(r.Challenges) == 0 {
			continue
		}
		if !challengesAvailable(r, registeredTypes) {
			continue
		}
		if len(r.Conditions) == 0 {
			return r.Challenges
		}
		if hasRegisteredCondition(r.Conditions, registeredTypes) {
			continue
		}
		return r.Challenges
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
// non-password challenge type registered.
func hasAnyChallenges(challenges []string, registeredTypes map[string]bool) bool {
	for _, ch := range challenges {
		if ch == PasswordKeyword {
			continue
		}
		if isTypeRegistered(ch, registeredTypes) {
			return true
		}
	}
	return false
}

// isTypeRegistered checks whether a challenge type is registered.
// The mfa type is a logical union of totp and u2f.
func isTypeRegistered(ch string, registeredTypes map[string]bool) bool {
	if ch == MfaKeyword {
		return registeredTypes[TotpKeyword] || registeredTypes[U2fKeyword]
	}
	return registeredTypes[ch]
}

// hasRegisteredCondition checks whether any condition type is
// registered, meaning the "not available" condition is not met.
func hasRegisteredCondition(conditions []string, registeredTypes map[string]bool) bool {
	for _, cond := range conditions {
		if registeredTypes[cond] {
			return true
		}
	}
	return false
}
