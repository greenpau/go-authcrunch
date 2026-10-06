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

// Package parser decodes required external-authorization policy bindings.
package parser

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewExternalAuthorizationConfigFromDirectives parses a complete encoded block
// body, without header/braces. Settings occur once except attribute declarations.
// Use cfgutil.EncodeArgs for values containing spaces. No I/O is performed.
func NewExternalAuthorizationConfigFromDirectives(statements []string) (*external.Config, error) {
	c := &external.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*external.Config, error) {
			return nil, fmt.Errorf("invalid external authorization directive at line %d", i+1)
		}
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return invalid()
		}
		name, value := args[0], args[len(args)-1]
		if name == "subject" || name == "tenant" {
			if len(args) != 3 || args[1] != "claim" {
				return invalid()
			}
		} else if len(args) != 2 {
			return invalid()
		}
		if strings.TrimSpace(value) == "" || name != "attribute" && seen[name] {
			return invalid()
		}
		seen[name] = true
		switch name {
		case "policy":
			c.Policy = value
		case "version":
			c.Version = value
		case "issuer":
			c.Issuer = value
		case "realm":
			c.Realm = value
		case "subject":
			c.SubjectClaim = value
		case "tenant":
			c.TenantClaim = value
		case "attribute":
			c.Attributes = append(c.Attributes, value)
		case "timeout":
			c.Timeout = value
		default:
			return invalid()
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
