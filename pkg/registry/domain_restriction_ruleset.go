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

import "fmt"

// DomainRestrictionRuleset holds the rules associated with domain restrictions.
type DomainRestrictionRuleset struct {
	rules         []*DomainRestrictionRule
	defaultAction actionKind
	statements    []string
}

// NewDomainRestrictionRuleset return an instance of DomainRuleset.
func NewDomainRestrictionRuleset(statements []string) (*DomainRestrictionRuleset, error) {
	ruleset := &DomainRestrictionRuleset{
		statements: statements,
	}
	if len(statements) < 1 {
		return nil, fmt.Errorf("no rule statements found")
	}
	var lastAction actionKind
	for _, statement := range statements {
		rule, err := NewDomainRestrictionRule(statement)
		if err != nil {
			return nil, err
		}
		ruleset.rules = append(ruleset.rules, rule)
		lastAction = rule.action
	}

	if lastAction == actionAllow {
		ruleset.defaultAction = actionDeny
	} else {
		ruleset.defaultAction = actionAllow
	}

	return ruleset, nil
}
