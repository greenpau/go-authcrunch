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

// Package parser decodes host-independent request-time enrichment bindings.
package parser

import (
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewClaimsEnrichmentConfigFromDirectives parses a complete block body encoded
// with cfgutil.EncodeArgs, without its header or braces. Scalar settings occur
// once: source, version, issuer, realm, audience, timeout, max age, subject claim,
// and tenant claim. Repeat attribute <name> string [list] or attribute <name> json for each
// allowed output. Timeout and max age default to 1s and 1m; bindings have no defaults.
func NewClaimsEnrichmentConfigFromDirectives(statements []string) (*enrichment.Config, error) {
	c := &enrichment.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*enrichment.Config, error) {
			return nil, fmt.Errorf("invalid claims enrichment directive at line %d", i+1)
		}
		if strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return invalid()
		}
		for _, a := range args {
			if strings.TrimSpace(a) == "" {
				return invalid()
			}
		}
		key := args[0]
		if key == "attribute" {
			if len(args) != 3 && len(args) != 4 {
				return invalid()
			}
			if (args[2] != "string" && args[2] != "json") || (len(args) == 4 && (args[2] != "string" || args[3] != "list")) {
				return invalid()
			}
			kind := args[2]
			if len(args) == 4 {
				kind = "string_list"
			}
			c.Attributes = append(c.Attributes, enrichment.AttributeConfig{Name: args[1], Type: kind})
			continue
		}
		if seen[key] {
			return invalid()
		}
		seen[key] = true
		switch key {
		case "subject", "tenant", "max":
			if len(args) != 3 {
				return invalid()
			}
			if key == "max" {
				if args[1] != "age" {
					return invalid()
				}
				c.MaxAge = args[2]
			} else {
				if args[1] != "claim" {
					return invalid()
				}
				if key == "subject" {
					c.SubjectClaim = args[2]
				} else {
					c.TenantClaim = args[2]
				}
			}
		default:
			if len(args) != 2 {
				return invalid()
			}
			switch key {
			case "source":
				c.Source = args[1]
			case "version":
				c.Version = args[1]
			case "issuer":
				c.Issuer = args[1]
			case "realm":
				c.Realm = args[1]
			case "audience":
				c.Audience = args[1]
			case "timeout":
				c.Timeout = args[1]
			default:
				return invalid()
			}
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
