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

// Package parser decodes token refresh directives into validated portal configuration.
// It accepts encoded statements independently of any embedding server or block parser.
package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewTokenRefreshConfigFromDirectives decodes statements from a portal "token
// refresh" block. Pass its directive lines, encoded with cfgutil.EncodeArgs, without
// braces or the block header. Encode each keyword as a separate argument, e.g.
// []string{"public", "origin", "https://auth.example.com"}. The returned config
// is enabled unless a standalone "disabled" directive is supplied. An absent
// block should remain a nil *authn.TokenRefreshConfig.
// An omitted cookie name stays empty to inherit the portal cookie factory's
// name and prefix. An explicit name overrides its refresh-token cookie setting.
//
// Each setting may occur once. "realms" takes one or more values. "public
// origin", "base path", and "cookie name" each take one value. "access lifetime",
// "idle timeout", "absolute timeout", "max sessions", and "max rotations" take
// one decimal integer; durations are seconds and zero retains Validate's defaults.
// "enabled" and "disabled" are mutually exclusive standalone directives. "body
// transport enabled" and "body transport disabled" select native body transport,
// which defaults to disabled. Boolean literals and underscore keys are rejected.
//
// Unknown directives, duplicates, empty values, and malformed statements fail.
// Reject empty argument values before encoding: EncodeArgs can trim a final
// empty field, which this parser cannot recover from the encoded statement.
// Resolve values before calling this constructor; it performs no environment
// expansion. authn.TokenRefreshConfig.Validate supplies defaults and checks the
// resulting config, including its opt-out behavior for disabled configurations.
func NewTokenRefreshConfigFromDirectives(statements []string) (*authn.TokenRefreshConfig, error) {
	config := &authn.TokenRefreshConfig{Enabled: true}
	stringsByKey := map[string]*string{
		"public origin": &config.PublicOrigin,
		"base path":     &config.BasePath,
		"cookie name":   &config.CookieName,
	}
	boolsByKey := map[string]*bool{
		"enabled":        &config.Enabled,
		"body transport": &config.BodyTransportEnabled,
	}
	intsByKey := map[string]*int{
		"access lifetime":  &config.AccessLifetimeSeconds,
		"idle timeout":     &config.IdleTimeoutSeconds,
		"absolute timeout": &config.AbsoluteTimeoutSeconds,
		"max sessions":     &config.MaxSessions,
		"max rotations":    &config.MaxRotations,
	}
	seen := make(map[string]bool)
	for i, statement := range statements {
		// DecodeArgs reads one CSV record. Reject newlines so subsequent records
		// cannot hide settings that the decoder would silently discard.
		if strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid token refresh directive at line %d", i+1)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 {
			return nil, fmt.Errorf("invalid token refresh directive at line %d", i+1)
		}
		key := args[0]
		values := args[1:]
		switch key {
		case "enabled", "disabled":
			if len(args) != 1 {
				return nil, fmt.Errorf("token refresh %s at line %d does not take arguments", key, i+1)
			}
			// Both spellings configure the same setting; even conflicting states
			// must be detected as duplicates rather than overwrite one another.
			key, values = "enabled", args
		case "realms":
		default:
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid token refresh directive at line %d", i+1)
			}
			// Match separate keyword tokens, preserving quoted value boundaries.
			key, values = args[0]+" "+args[1], args[2:]
		}
		if key != "realms" && stringsByKey[key] == nil && boolsByKey[key] == nil && intsByKey[key] == nil {
			return nil, fmt.Errorf("unsupported token refresh directive at line %d", i+1)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("token refresh directive %s at line %d requires a value", key, i+1)
		}
		if key != "realms" && len(values) != 1 {
			return nil, fmt.Errorf("token refresh directive %s at line %d requires one value", key, i+1)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate token refresh directive %s at line %d", key, i+1)
		}
		seen[key] = true
		if slices.Contains(values, "") {
			return nil, fmt.Errorf("empty token refresh directive %s value at line %d", key, i+1)
		}
		switch {
		case key == "realms":
			config.Realms = values
		case stringsByKey[key] != nil:
			*stringsByKey[key] = values[0]
		case boolsByKey[key] != nil:
			if values[0] != "enabled" && values[0] != "disabled" {
				return nil, fmt.Errorf("token refresh directive %s at line %d requires enabled or disabled", key, i+1)
			}
			*boolsByKey[key] = values[0] == "enabled"
		case intsByKey[key] != nil:
			value, err := strconv.Atoi(values[0])
			if err != nil {
				return nil, fmt.Errorf("invalid token refresh integer %s at line %d", key, i+1)
			}
			*intsByKey[key] = value
		}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
