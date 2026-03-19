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

// Evaluate returns the challenge list from the first matching
// rule, or nil if no rules match.
func (rs *Ruleset) Evaluate(registeredTypes map[string]bool) []string {
	for _, r := range rs.rules {
		if r == nil || len(r.challenges) == 0 {
			continue
		}
		if r.hasOr && !hasAnyChallenges(r.challenges, registeredTypes) {
			continue
		}
		if !r.hasOr && !hasAllChallenges(r.challenges, registeredTypes) {
			continue
		}
		if len(r.conditions) == 0 {
			return r.challenges
		}
		if !hasRegisteredCondition(r.conditions, registeredTypes) {
			return r.challenges
		}
	}
	return nil
}

// hasAllChallenges checks whether the user has all non-password
// challenge types registered.
func hasAllChallenges(challenges []string, registeredTypes map[string]bool) bool {
	for _, ch := range challenges {
		if ch == passwordKeyword {
			continue
		}
		if !registeredTypes[ch] {
			return false
		}
	}
	return true
}

// hasAnyChallenges checks whether the user has at least one
// non-password challenge type registered.
func hasAnyChallenges(challenges []string, registeredTypes map[string]bool) bool {
	for _, ch := range challenges {
		if ch == passwordKeyword {
			continue
		}
		if registeredTypes[ch] {
			return true
		}
	}
	return false
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
