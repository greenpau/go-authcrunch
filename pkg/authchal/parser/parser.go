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

// Package parser decodes reusable authentication challenge directives.
package parser

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authchal/config"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewAuthenticationChallengeConfigFromDirectives parses encoded rule bodies
// after "auth challenges" (no prefix or braces). A rule is a sequence of methods
// or an ordered list separated by "or", optionally followed by
// "if <method> [and <method> ...] not available". Rules are tried in order.
// Methods are password, totp, u2f, mfa, and email; consumers may support a subset.
// Empty policies, mixed AND/OR sequences, duplicate rules, and malformed syntax
// fail without a partial result or raw input in errors. Reject empty arguments
// before EncodeArgs, which can discard a trailing empty token.
func NewAuthenticationChallengeConfigFromDirectives(statements []string) (*config.AuthenticationChallengeConfig, error) {
	c := &config.AuthenticationChallengeConfig{}
	seen := map[string]bool{}
	for i, s := range statements {
		args, err := cfgutil.DecodeArgs(s)
		if err != nil || !utf8.ValidString(s) || strings.ContainsAny(s, "\r\n") || len(args) == 0 || slices.Contains(args, "") {
			return nil, fmt.Errorf("invalid authentication challenge directive at line %d", i+1)
		}
		r, err := parseRule(args)
		if err != nil {
			return nil, fmt.Errorf("authentication challenge directive at line %d: %w", i+1, err)
		}
		canonical := cfgutil.EncodeArgs(args)
		if seen[canonical] {
			return nil, fmt.Errorf("duplicate authentication challenge directive at line %d", i+1)
		}
		seen[canonical] = true
		c.Statements = append(c.Statements, canonical)
		c.Rules = append(c.Rules, r)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func parseRule(args []string) (*config.Rule, error) {
	r := &config.Rule{}
	split := slices.Index(args, "if")
	methods := args
	if split >= 0 {
		methods = args[:split]
		condition := args[split+1:]
		if len(condition) < 3 || condition[len(condition)-2] != "not" || condition[len(condition)-1] != "available" {
			return nil, fmt.Errorf("invalid availability condition")
		}
		condition = condition[:len(condition)-2]
		for i, ch := range condition {
			if i%2 == 1 {
				if ch != "and" {
					return nil, fmt.Errorf("conditions require and separators")
				}
				continue
			}
			r.Conditions = append(r.Conditions, ch)
		}
		if len(condition)%2 == 0 {
			return nil, fmt.Errorf("missing condition method")
		}
	}
	r.HasOr = slices.Contains(methods, "or")
	if r.HasOr {
		if len(methods)%2 == 0 {
			return nil, fmt.Errorf("missing alternative method")
		}
		for i, ch := range methods {
			if i%2 == 1 {
				if ch != "or" {
					return nil, fmt.Errorf("mixed challenge sequence and alternatives")
				}
				continue
			}
			r.Challenges = append(r.Challenges, ch)
		}
	} else {
		r.Challenges = slices.Clone(methods)
	}
	c := &config.AuthenticationChallengeConfig{Rules: []*config.Rule{r}}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}
