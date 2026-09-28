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

// Package parser decodes reusable ACL field declarations independently of a host.
package parser

import (
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewACLFieldConfigFromDirectives parses the body of a named ACL field block:
//
//	claim <literal-top-level-key>
//	type string
//	type string list
//
// Supply exactly one claim statement and one type statement, encoded separately
// with cfgutil.EncodeArgs; do not include the block header or braces. Neither
// setting has a default. Hosts must reject empty tokens before encoding, which
// can discard trailing empty fields. Names are policy-local ASCII identifiers;
// claim keys are literal and may contain URL punctuation, commas and spaces.
// Collect all fields before validating the policy to catch duplicate names and
// allow rules to precede their declarations. Errors contain no input values;
// failures return nil and never mutate the supplied statements.
func NewACLFieldConfigFromDirectives(name string, statements []string) (*acl.FieldConfig, error) {
	config := &acl.FieldConfig{Name: name}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*acl.FieldConfig, error) {
			return nil, fmt.Errorf("invalid ACL field directive at line %d", i+1)
		}
		if strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 || seen[args[0]] {
			return invalid()
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return invalid()
			}
		}
		seen[args[0]] = true
		switch args[0] {
		case "claim":
			if len(args) != 2 {
				return invalid()
			}
			config.Claim = args[1]
		case "type":
			switch {
			case len(args) == 2 && args[1] == "string":
				config.Type = acl.FieldTypeString
			case len(args) == 3 && args[1] == "string" && args[2] == "list":
				config.Type = acl.FieldTypeStringList
			default:
				return invalid()
			}
		default:
			return invalid()
		}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
