// Copyright 2024 Paul Greenberg greenpau@outlook.com
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

package registry

import "strings"

// ShouldDeny returns true if domain name is not allowed
func (rs *DomainRestrictionRuleset) ShouldDeny(domainStr string) bool {
	domainMatched := false
	action := rs.defaultAction

	for _, rule := range rs.rules {
		switch rule.domainMatch {
		case matchExact:
			if rule.Domain == domainStr {
				domainMatched = true
			}
		case matchPartial:
			if strings.Contains(domainStr, rule.Domain) {
				domainMatched = true
			}
		case matchPrefix:
			if strings.HasPrefix(domainStr, rule.Domain) {
				domainMatched = true
			}
		case matchSuffix:
			if strings.HasSuffix(domainStr, rule.Domain) {
				domainMatched = true
			}
		case matchRegex:
			if rule.domainRegex.MatchString(domainStr) {
				domainMatched = true
			}
		}
		if domainMatched {
			action = rule.action
			break
		}
	}

	if action == actionAllow {
		return false
	}
	return true
}
