// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

// Package logging configures opt-in suppression of diagnostic log entries.
package logging

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Config contains independently matching skip rules. Omitted and empty
// configurations retain all entries. Rules affect logging, never authorization.
type Config struct {
	Skip     []SkipRule `json:"skip,omitempty" xml:"skip,omitempty" yaml:"skip,omitempty"`
	compiled []compiledRule
}

// SkipRule suppresses an entry when its message or a textual field value matches
// Text. Match is one of exact, partial, prefix, suffix, or regex, as in transforms.
// Each value is matched independently and case-sensitively. Regex uses Go's
// regexp syntax and is unanchored unless the expression supplies anchors.
type SkipRule struct {
	Match string `json:"match,omitempty" xml:"match,omitempty" yaml:"match,omitempty"`
	Text  string `json:"text,omitempty" xml:"text,omitempty" yaml:"text,omitempty"`
}

const (
	matchExact   = "exact"
	matchPartial = "partial"
	matchPrefix  = "prefix"
	matchSuffix  = "suffix"
	matchRegex   = "regex"
)

type compiledRule struct {
	SkipRule
	expression *regexp.Regexp
}

// Validate checks all rules and compiles regular expressions. Errors identify
// the rule without echoing configured text. Revalidation replaces compiled state.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("logging config is nil")
	}
	rules := make([]compiledRule, 0, len(c.Skip))
	for i, rule := range c.Skip {
		if strings.TrimSpace(rule.Text) == "" || !utf8.ValidString(rule.Text) || strings.ContainsAny(rule.Text, "\r\n") {
			return fmt.Errorf("logging skip rule %d has invalid text", i+1)
		}
		compiled := compiledRule{SkipRule: rule}
		switch rule.Match {
		case matchExact, matchPartial, matchPrefix, matchSuffix:
		case matchRegex:
			expression, err := regexp.Compile(rule.Text)
			if err != nil {
				return fmt.Errorf("logging skip rule %d has invalid regex", i+1)
			}
			compiled.expression = expression
		default:
			return fmt.Errorf("logging skip rule %d has unsupported matcher", i+1)
		}
		rules = append(rules, compiled)
	}
	c.compiled = rules
	return nil
}

func (r compiledRule) matches(text string) bool {
	switch r.Match {
	case matchExact:
		return text == r.Text
	case matchPartial:
		return strings.Contains(text, r.Text)
	case matchPrefix:
		return strings.HasPrefix(text, r.Text)
	case matchSuffix:
		return strings.HasSuffix(text, r.Text)
	case matchRegex:
		return r.expression.MatchString(text)
	}
	return false
}
