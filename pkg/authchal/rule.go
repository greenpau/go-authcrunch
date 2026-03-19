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

import (
	"fmt"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

const (
	// PasswordKeyword is the password challenge type.
	PasswordKeyword = "password"
	// TotpKeyword is the TOTP challenge type.
	TotpKeyword = "totp"
	// U2fKeyword is the U2F challenge type.
	U2fKeyword = "u2f"
	// MfaKeyword is the mixed MFA challenge type (soft or hard token).
	MfaKeyword = "mfa"

	orKeyword        = "or"
	ifKeyword        = "if"
	andKeyword       = "and"
	notKeyword       = "not"
	availableKeyword = "available"
)

var validChallengeTypes = map[string]bool{
	PasswordKeyword: true,
	TotpKeyword:     true,
	U2fKeyword:      true,
	MfaKeyword:      true,
}

// Rule holds a parsed auth challenge rule.
type Rule struct {
	Challenges []string `json:"challenges,omitempty" xml:"challenges,omitempty" yaml:"challenges,omitempty"`
	Conditions []string `json:"conditions,omitempty" xml:"conditions,omitempty" yaml:"conditions,omitempty"`
	HasOr      bool     `json:"has_or,omitempty" xml:"has_or,omitempty" yaml:"has_or,omitempty"`
}

func parseRule(s string) (*Rule, error) {
	args, err := cfgutil.DecodeArgs(s)
	if err != nil {
		return nil, fmt.Errorf("auth challenge rule: %v", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty auth challenge rule")
	}

	r := &Rule{}
	seen := make(map[string]bool)
	i := 0

	for i < len(args) && args[i] != ifKeyword {
		ch := args[i]
		if ch == orKeyword {
			r.HasOr = true
			i++
			continue
		}
		if !validChallengeTypes[ch] {
			return nil, fmt.Errorf("unsupported challenge type: %s", ch)
		}
		if seen[ch] {
			return nil, fmt.Errorf("duplicate challenge type: %s", ch)
		}
		seen[ch] = true
		r.Challenges = append(r.Challenges, ch)
		i++
	}
	if len(r.Challenges) == 0 {
		return nil, fmt.Errorf("no challenge types specified")
	}

	if i >= len(args) {
		return r, nil
	}

	// Skip "if", parse condition types, skip "and" and "not available".
	i++ // skip "if"
	for i < len(args) {
		tok := args[i]
		if tok == andKeyword || tok == notKeyword || tok == availableKeyword {
			i++
			continue
		}
		if !validChallengeTypes[tok] {
			return nil, fmt.Errorf("unsupported condition type: %s", tok)
		}
		if seen[tok] {
			return nil, fmt.Errorf("condition type %s conflicts with challenge type", tok)
		}
		r.Conditions = append(r.Conditions, tok)
		i++
	}
	if len(r.Conditions) == 0 {
		return nil, fmt.Errorf("empty condition in auth challenge rule")
	}

	return r, nil
}
