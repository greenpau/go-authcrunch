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

import (
	"fmt"
	"regexp"
	"strings"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

type matchStrategy int

const (
	matchUnknown matchStrategy = 0
	matchExact   matchStrategy = 1
	matchPartial matchStrategy = 2
	matchPrefix  matchStrategy = 3
	matchSuffix  matchStrategy = 4
	matchRegex   matchStrategy = 5
)

type actionKind int

const (
	unknownAction actionKind = 0
	actionDeny    actionKind = 1
	actionAllow   actionKind = 2
)

// DomainRestrictionRule holds the configuration for a domain restriction.
type DomainRestrictionRule struct {
	DomainMatchType string `json:"domain_match_type,omitempty" xml:"domain_match_type,omitempty" yaml:"domain_match_type,omitempty"`
	Domain          string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
	ActionType      string `json:"action_type,omitempty" xml:"action_type,omitempty" yaml:"action_type,omitempty"`
	domainMatch     matchStrategy
	domainRegex     *regexp.Regexp
	action          actionKind
}

// NewDomainRestrictionRule return an instance of *DomainRestrictionRule.
func NewDomainRestrictionRule(statement string) (*DomainRestrictionRule, error) {
	decodedArgs, err := cfgutil.DecodeArgs(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to decode domain restriction rule: %s", statement)
	}

	var actionType, domainMatchType, domainStr string

	switch len(decodedArgs) {
	case 3:
		actionType = decodedArgs[0]
		domainMatchType = "exact"
		domainStr = decodedArgs[2]
	case 4:
		actionType = decodedArgs[0]
		domainMatchType = decodedArgs[1]
		domainStr = decodedArgs[3]
	default:
		return nil, fmt.Errorf("malformed domain restriction rule: %s", statement)
	}

	if decodedArgs[len(decodedArgs)-2] != "domain" {
		return nil, fmt.Errorf("malformed domain restriction rule, syntax: <allow|deny> [exact|partial|prefix|suffix|regex] domain <string>")
	}

	r := &DomainRestrictionRule{
		DomainMatchType: strings.TrimSpace(domainMatchType),
		Domain:          strings.TrimSpace(domainStr),
		ActionType:      strings.TrimSpace(actionType),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate validates RedirectURIMatchConfig.
func (r *DomainRestrictionRule) Validate() error {
	switch r.DomainMatchType {
	case "exact":
		r.domainMatch = matchExact
	case "partial":
		r.domainMatch = matchPartial
	case "prefix":
		r.domainMatch = matchPrefix
	case "suffix":
		r.domainMatch = matchSuffix
	case "regex":
		r.domainMatch = matchRegex
	case "":
		r.domainMatch = matchUnknown
		return fmt.Errorf("undefined domain name match type")
	default:
		r.domainMatch = matchUnknown
		return fmt.Errorf("invalid %q domain name match type", r.DomainMatchType)
	}

	r.Domain = strings.TrimSpace(r.Domain)

	if r.Domain == "" {
		return fmt.Errorf("undefined domain")
	}

	if r.domainRegex == nil {
		rgx, err := regexp.Compile(r.Domain)
		if err != nil {
			return err
		}
		r.domainRegex = rgx
	}

	switch r.ActionType {
	case "allow":
		r.action = actionAllow
	case "deny":
		r.action = actionDeny
	case "":
		r.action = unknownAction
		return fmt.Errorf("undefined action type")
	default:
		r.action = unknownAction
		return fmt.Errorf("invalid %q action type", r.ActionType)
	}

	return nil
}
