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

// Package parser decodes admin API directives into portal API configuration,
// independently of an embedding server's configuration syntax or runtime.
package parser

import (
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewAdminAPIConfigFromDirectives decodes complete portal directive statements:
//
//	enable admin api
//	disable admin api
//	enable admin api private key export
//	disable admin api private key export
//
// Encode each statement with cfgutil.EncodeArgs, with each keyword in a separate
// argument. Pass no braces or unrelated portal directives. Each setting may occur
// only once, including its opposite state. Keywords are lowercase; underscore
// keys, boolean literals, unknown directives, and malformed statements fail with
// no partial result. Errors identify the line without including input values.
// Reject empty arguments before encoding: EncodeArgs can trim a trailing empty
// field, which this parser cannot recover.
//
// Both admin settings default to false, including for an empty directive list.
// Private-key export never implicitly enables the admin API; the portal requires
// both flags and authenticated admin authorization before exporting keys.
//
// Apply the returned authn.AdminAPIConfig with PortalConfig.ConfigureAdminAPI
// after successful parsing. That method preserves independently configured
// profile access and the portal's established serialized API fields.
// Collect all admin directives before calling so duplicate detection spans the
// entire portal configuration. No inputs or existing configurations are mutated.
func NewAdminAPIConfigFromDirectives(statements []string) (*authn.AdminAPIConfig, error) {
	config := &authn.AdminAPIConfig{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		// DecodeArgs reads one CSV record; do not silently discard another line.
		if strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid admin API directive at line %d", i+1)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || (len(args) != 3 && len(args) != 6) {
			return nil, fmt.Errorf("invalid admin API directive at line %d", i+1)
		}
		if (args[0] != "enable" && args[0] != "disable") || args[1] != "admin" || args[2] != "api" {
			return nil, fmt.Errorf("unsupported admin API directive at line %d", i+1)
		}
		key, target := "admin api", &config.Enabled
		if len(args) == 6 {
			if args[3] != "private" || args[4] != "key" || args[5] != "export" {
				return nil, fmt.Errorf("unsupported admin API directive at line %d", i+1)
			}
			key, target = "admin api private key export", &config.FetchPrivateKeysEnabled
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate admin API setting %s at line %d", key, i+1)
		}
		seen[key] = true
		*target = args[0] == "enable"
	}
	return config, nil
}
