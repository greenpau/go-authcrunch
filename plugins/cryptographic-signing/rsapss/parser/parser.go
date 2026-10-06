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

// Package parser decodes PS256 signing configuration without loading keys.
package parser

import (
	"fmt"
	"strings"
	"unicode/utf8"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	signing "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
)

// NewRSAPSSSigningConfigFromDirectives parses a complete encoded block body,
// without its header or braces. Each setting occurs once: key file, key id,
// algorithm, issuer, audience, and max lifetime. Use cfgutil.EncodeArgs for paths
// or values with spaces. Algorithm and max lifetime default to PS256 and 15m.
func NewRSAPSSSigningConfigFromDirectives(statements []string) (*signing.Config, error) {
	c := &signing.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*signing.Config, error) {
			return nil, fmt.Errorf("invalid PS256 signing directive at line %d", i+1)
		}
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return invalid()
		}
		var field *string
		var name, value string
		switch args[0] {
		case "key", "max":
			if len(args) != 3 {
				return invalid()
			}
			name, value = args[0]+" "+args[1], args[2]
			switch name {
			case "key file":
				field = &c.KeyFile
			case "key id":
				field = &c.KeyID
			case "max lifetime":
				field = &c.MaxLifetime
			default:
				return invalid()
			}
		default:
			if len(args) != 2 {
				return invalid()
			}
			name, value = args[0], args[1]
			switch name {
			case "algorithm":
				field = &c.Algorithm
			case "issuer":
				field = &c.Issuer
			case "audience":
				field = &c.Audience
			default:
				return invalid()
			}
		}
		if seen[name] || strings.TrimSpace(value) == "" {
			return invalid()
		}
		seen[name], *field = true, value
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
