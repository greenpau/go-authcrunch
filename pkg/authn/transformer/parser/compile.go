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

package parser

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authchal"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/config"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// CompileUserTransformerConfig validates and snapshots the established serialized
// matcher/action lists. Both typed configuration and block parsing share this
// decoder. The result contains independent runtime data and starts no workers.
func CompileUserTransformerConfig(cfg *config.Config) (*config.RuntimeConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil transformer config")
	}
	if len(cfg.Matchers) < 1 {
		return nil, fmt.Errorf("transformer has no matchers")
	}
	if len(cfg.Actions) < 1 {
		return nil, fmt.Errorf("transformer has no actions")
	}

	var actions [][]string
	var challengeStatements []string
	for _, encodedArgs := range cfg.Actions {
		args, err := cfgutil.DecodeArgs(encodedArgs)
		if err != nil || len(args) == 0 || hasEmptyArgument(args) || !utf8.ValidString(encodedArgs) || strings.ContainsAny(encodedArgs, "\r\n") {
			return nil, fmt.Errorf("invalid transformer action")
		}
		if args[0] == "action" {
			if len(args) < 2 || !slices.Contains([]string{"add", "overwrite", "delete", "drop"}, args[1]) {
				return nil, fmt.Errorf("invalid transformer action alias")
			}
			args = args[1:]
		}
		switch args[0] {
		case "require":
			if len(args) >= 3 && args[1] == "auth" && args[2] == "challenges" {
				challengeStatements = append(challengeStatements, cfgutil.EncodeArgs(args[3:]))
			} else if len(args) != 2 || !slices.Contains([]string{"password", "mfa", "totp", "u2f"}, args[1]) {
				return nil, fmt.Errorf("invalid required authentication challenge")
			}
			actions = append(actions, args)
		case "block", "deny":
			if len(args) != 1 {
				return nil, fmt.Errorf("block/deny takes no arguments")
			}
			actions = append(actions, args)
		case "ui":
			if len(args) < 4 {
				return nil, fmt.Errorf("transformer ui config too short")
			}
			switch args[1] {
			case "link":
				actions = append(actions, args[1:])
			default:
				return nil, fmt.Errorf("transformer invalid ui config")
			}
		case "drop":
			if len(args) != 3 || args[1] != "matched" || args[2] != "role" {
				return nil, fmt.Errorf("drop requires matched role")
			}
			actions = append(actions, args)
		case "add", "overwrite":
			if len(args) < 3 {
				return nil, fmt.Errorf("transformer invalid add/overwrite config")
			}
			if _, kind := acl.GetFieldDataType(args[1]); kind == "" {
				if args[0] == "overwrite" {
					return nil, fmt.Errorf("overwrite requires a supported field")
				}
				var err error
				if args[1] == "nested" {
					_, _, err = ParseCustomNestedFieldValues(args[2:])
				} else {
					_, err = ParseCustomFieldValues(args[2:])
				}
				if err != nil {
					return nil, err
				}
			}
			actions = append(actions, args)
		case "delete":
			if len(args) != 2 {
				return nil, fmt.Errorf("delete requires one field")
			}
			actions = append(actions, args)
		default:
			return nil, fmt.Errorf("transformer has unsupported action")
		}
	}
	for _, statement := range cfg.Matchers {
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 || hasEmptyArgument(args) || !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid transformer matcher")
		}
	}
	matcher := acl.NewAccessList()
	matchRuleConfigs := []*acl.RuleConfiguration{
		{
			Conditions: slices.Clone(cfg.Matchers),
			Action:     "allow",
		},
	}
	if err := matcher.AddRules(context.Background(), matchRuleConfigs); err != nil {
		return nil, fmt.Errorf("invalid transformer matcher")
	}
	tr := &config.RuntimeConfig{Matcher: matcher, Actions: actions}
	if len(challengeStatements) > 0 {
		rules, err := authchal.NewRuleset(challengeStatements)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules.Rules {
			if slices.Contains(rule.Challenges, authchal.EmailKeyword) || slices.Contains(rule.Conditions, authchal.EmailKeyword) {
				return nil, fmt.Errorf("email authentication checkpoints are unsupported")
			}
		}
		tr.AuthenticationChallenges = rules
	}
	return tr, nil
}
