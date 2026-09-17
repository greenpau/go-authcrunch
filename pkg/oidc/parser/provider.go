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

package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewOIDCProviderConfigFromDirectives decodes an "oidc provider" block body
// into configuration suitable for oidc.NewProvider or authn.PortalConfig.OIDCProvider.
// Pass statements encoded with cfgutil.EncodeArgs, without the header or braces.
// Encode each keyword separately, e.g. {"signing", "key", "files", "oidc.pem"}.
// The embedding application resolves placeholders and parses application blocks
// before calling this function; the parser does not expand environment variables.
//
// "issuer" takes one value. "realms", "signing key files", and "applications"
// take one or more. "session lifetime", "token lifetime", "max sessions",
// "refresh lifetime", "max pending requests", "max refresh tokens", and
// "max grants" take one decimal integer; lifetimes
// are seconds and zero retains oidc.Config.Validate defaults. Standalone
// "enabled" or "disabled" selects the state, which defaults to enabled.
// Boolean literals and underscore keys are not accepted. Each setting occurs
// once except repeatable "acr <value> <method>..." mappings with distinct values.
// Unknown settings, duplicates, empty values, and malformed statements fail.
// Reject empty arguments before encoding: EncodeArgs can trim a final empty field.
// An absent block should remain a nil *oidc.Config.
//
// "applications" selects registrations by exact nickname in applications, in
// directive order. Nicknames are host-owned labels, independent of client IDs
// and display names; the host enforces nickname uniqueness when building the map.
// Only selected registrations are copied and validated with Config.AddClient,
// before final provider validation. Unknown/nil registrations, repeated references,
// and duplicate client IDs fail, even when the provider is disabled. Other disabled
// settings retain Config.Validate's opt-out behavior. No partial result is returned.
//
// This function never generates credentials, reads keys, or mutates registrations.
// Provision and persist clients separately with NewOIDCClientConfigFromDirectives
// or oidc.NewClientConfig. Key files are loaded when constructing the provider.
// Concurrent calls may share inputs provided callers do not modify them concurrently.
func NewOIDCProviderConfigFromDirectives(statements []string, applications map[string]*oidc.ClientConfig) (*oidc.Config, error) {
	config := &oidc.Config{Enabled: true}
	var references []string
	lists := map[string]*[]string{
		"realms":            &config.Realms,
		"signing key files": &config.SigningKeyFiles,
		"applications":      &references,
	}
	integers := map[string]*int{
		"session lifetime":     &config.SessionLifetimeSeconds,
		"token lifetime":       &config.TokenLifetimeSeconds,
		"refresh lifetime":     &config.RefreshLifetimeSeconds,
		"max refresh tokens":   &config.MaxRefreshTokens,
		"max sessions":         &config.MaxSessions,
		"max pending requests": &config.MaxPendingRequests,
		"max grants":           &config.MaxGrants,
	}
	seen := make(map[string]bool)
	for i, statement := range statements {
		// DecodeArgs reads one CSV record. Do not silently discard another line.
		if strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid oidc provider directive at line %d", i+1)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 {
			return nil, fmt.Errorf("invalid oidc provider directive at line %d", i+1)
		}
		words := 1
		switch args[0] {
		case "enabled", "disabled", "issuer", "realms", "applications", "acr":
		case "session", "token", "refresh", "max":
			words = 2
			if args[0] == "max" && len(args) > 1 && (args[1] == "pending" || args[1] == "refresh") {
				words = 3
			}
		case "signing":
			words = 3
		default:
			return nil, fmt.Errorf("unsupported oidc provider directive at line %d", i+1)
		}
		if len(args) < words {
			return nil, fmt.Errorf("invalid oidc provider directive at line %d", i+1)
		}
		key, values := strings.Join(args[:words], " "), args[words:]
		// Joining must not let a quoted group stand in for separate keywords.
		if !slices.Equal(args[:words], strings.Split(key, " ")) {
			return nil, fmt.Errorf("unsupported oidc provider directive at line %d", i+1)
		}
		if key == "enabled" || key == "disabled" {
			if len(args) != 1 {
				return nil, fmt.Errorf("oidc provider %s at line %d does not take arguments", key, i+1)
			}
			key, values = "enabled", args
		}
		if key == "acr" {
			if len(values) < 2 || slices.Contains(values, "") {
				return nil, fmt.Errorf("oidc acr requires a value and authentication methods at line %d", i+1)
			}
			config.AuthenticationContexts = append(config.AuthenticationContexts, oidc.AuthenticationContext{Value: values[0], Methods: values[1:]})
			continue
		}
		if key != "enabled" && key != "issuer" && lists[key] == nil && integers[key] == nil {
			return nil, fmt.Errorf("unsupported oidc provider directive at line %d", i+1)
		}
		if len(values) == 0 || (lists[key] == nil && len(values) != 1) {
			return nil, fmt.Errorf("invalid oidc provider directive %s argument count at line %d", key, i+1)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate oidc provider directive %s at line %d", key, i+1)
		}
		seen[key] = true
		if slices.Contains(values, "") {
			return nil, fmt.Errorf("empty oidc provider directive %s value at line %d", key, i+1)
		}
		switch {
		case key == "enabled":
			config.Enabled = values[0] == "enabled"
		case key == "issuer":
			config.Issuer = values[0]
		case lists[key] != nil:
			*lists[key] = values
		case integers[key] != nil:
			value, err := strconv.Atoi(values[0])
			if err != nil {
				return nil, fmt.Errorf("invalid oidc provider integer %s at line %d", key, i+1)
			}
			*integers[key] = value
		}
	}
	if err := addOIDCProviderApplications(config, references, applications); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

func addOIDCProviderApplications(config *oidc.Config, references []string, applications map[string]*oidc.ClientConfig) error {
	seen := make(map[string]bool, len(references))
	for i, nickname := range references {
		if nickname == "" || len(nickname) > 256 || strings.TrimSpace(nickname) != nickname || strings.ContainsAny(nickname, "\r\n\t") {
			return fmt.Errorf("invalid oidc application reference at position %d", i+1)
		}
		if seen[nickname] {
			return fmt.Errorf("duplicate oidc application reference at position %d", i+1)
		}
		seen[nickname] = true
		client, ok := applications[nickname]
		if !ok {
			return fmt.Errorf("unregistered oidc application reference at position %d", i+1)
		}
		if err := config.AddClient(client); err != nil {
			return fmt.Errorf("invalid oidc application reference at position %d: %w", i+1, err)
		}
	}
	return nil
}
