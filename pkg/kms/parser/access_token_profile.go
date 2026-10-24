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

// Package parser provides complete strict access-profile configuration parsing.
package parser

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/kms"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewAccessTokenProfileConfigFromDirectives parses a complete encoded flat body.
// Every setting is required exactly once; no expansion or file I/O is performed.
func NewAccessTokenProfileConfigFromDirectives(statements []string) (*kms.AccessTokenProfileConfig, error) {
	config := &kms.AccessTokenProfileConfig{}
	seen := map[string]bool{}
	for _, statement := range statements {
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return nil, fmt.Errorf("invalid access profile directive encoding")
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return nil, fmt.Errorf("invalid access token profile directive")
		}
		key := args[0]
		values := args[1:]
		if key == "key" || key == "max" {
			if len(args) < 3 {
				return nil, fmt.Errorf("invalid access token profile directive")
			}
			key += " " + args[1]
			values = args[2:]
		}
		if seen[key] || key != "key ids" && len(values) != 1 {
			return nil, fmt.Errorf("duplicate or malformed access token profile directive")
		}
		seen[key] = true
		switch key {
		case "issuer":
			config.Issuer = values[0]
		case "audience":
			config.Audience = values[0]
		case "key ids":
			config.KeyIDs = values
		case "max lifetime":
			value, err := strconv.Atoi(values[0])
			if err != nil {
				return nil, fmt.Errorf("invalid access profile lifetime")
			}
			config.MaxLifetimeSeconds = value
		default:
			return nil, fmt.Errorf("unknown access token profile directive")
		}
	}
	if len(seen) != 4 {
		return nil, fmt.Errorf("incomplete access token profile")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
