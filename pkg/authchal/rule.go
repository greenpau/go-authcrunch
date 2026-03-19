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

var validChallengeTypes = map[string]bool{
	"password": true,
	"totp":     true,
	"u2f":      true,
}

type rule struct {
	challenges []string
	conditions []string
	hasOr      bool
}

func parseRule(s string) (*rule, error) {
	args, err := cfgutil.DecodeArgs(s)
	if err != nil {
		return nil, fmt.Errorf("auth challenge rule: %v", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty auth challenge rule")
	}

	r := &rule{}
	seen := make(map[string]bool)
	i := 0

	for i < len(args) && args[i] != "if" {
		ch := args[i]
		if ch == "or" {
			r.hasOr = true
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
		r.challenges = append(r.challenges, ch)
		i++
	}
	if len(r.challenges) == 0 {
		return nil, fmt.Errorf("no challenge types specified")
	}

	if i >= len(args) {
		return r, nil
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
		r.conditions = append(r.conditions, tok)
		i++
	}
	if len(r.conditions) == 0 {
		return nil, fmt.Errorf("empty condition in auth challenge rule")
	}

	return r, nil
}
