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
	"encoding/json"
	"fmt"
)

// Ruleset holds parsed auth challenge rules.
type Ruleset struct {
	Rules      []*Rule  `json:"rules,omitempty" xml:"rules,omitempty" yaml:"rules,omitempty"`
	Statements []string `json:"statements,omitempty" xml:"statements,omitempty" yaml:"statements,omitempty"`
}

// NewRuleset parses a list of auth challenge rule statements.
func NewRuleset(statements []string) (*Ruleset, error) {
	if len(statements) == 0 {
		return nil, fmt.Errorf("no auth challenge rule statements found")
	}
	rs := &Ruleset{
		Statements: statements,
	}
	for _, s := range statements {
		r, err := parseRule(s)
		if err != nil {
			return nil, err
		}
		rs.Rules = append(rs.Rules, r)
	}
	return rs, nil
}

// Dump returns the JSON string representation of Ruleset.
func (rs *Ruleset) Dump() string {
	if rs == nil {
		return "{}"
	}
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return "{\"error\": \"" + err.Error() + "\"}"
	}
	return string(b)
}
