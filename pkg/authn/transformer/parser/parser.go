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

// Package parser decodes transform user block bodies independently of a host server.
package parser

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/config"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewUserTransformerConfigFromDirectives parses one transform user block body,
// without its header or braces. Match directives use the ACL grammar; actions
// use require, add, overwrite, delete, drop, action, ui, block, or deny.
// Repeated matchers/actions retain declaration order. Conditional requirements
// use "require auth challenges <rule>" and the authentication challenge grammar.
// The result can be appended to PortalConfig.UserTransformerConfigs. It owns its
// slices and is validated through the same constructor as typed configurations.
// Reject empty tokens before EncodeArgs. Errors never include raw directives.
func NewUserTransformerConfigFromDirectives(statements []string) (*config.Config, error) {
	c := &config.Config{}
	for i, s := range statements {
		args, err := cfgutil.DecodeArgs(s)
		if err != nil || len(args) == 0 || hasEmptyArgument(args) || !utf8.ValidString(s) || strings.ContainsAny(s, "\r\n") {
			return nil, fmt.Errorf("invalid user transformer directive at line %d", i+1)
		}
		switch args[0] {
		case "require", "add", "overwrite", "delete", "drop", "action", "ui", "block", "deny":
			c.Actions = append(c.Actions, cfgutil.EncodeArgs(args))
		case "match", "no", "exact", "partial", "prefix", "suffix", "regex", "field":
			c.Matchers = append(c.Matchers, cfgutil.EncodeArgs(args))
		default:
			return nil, fmt.Errorf("unsupported user transformer directive at line %d", i+1)
		}
	}
	if _, err := CompileUserTransformerConfig(c); err != nil {
		return nil, fmt.Errorf("invalid user transformer configuration")
	}
	return c, nil
}

func hasEmptyArgument(args []string) bool {
	return slices.ContainsFunc(args, func(arg string) bool { return strings.TrimSpace(arg) == "" })
}
