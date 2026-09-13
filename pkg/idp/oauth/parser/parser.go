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

// Package parser decodes upstream OAuth identity provider directives into typed
// configuration independently of an embedding server or running provider.
package parser

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewOAuthIdentityProviderConfigFromDirectives parses an upstream OAuth identity
// provider block body. Pass its name separately and encode each body statement
// with cfgutil.EncodeArgs. Do not pass the block header or braces. The embedding
// adapter owns tokenization and placeholder expansion. Parse the complete body
// in one call so duplicate checks span the entire provider definition.
//
// Scalar and list settings accept the existing serialized spelling, including
// "issuer" and "access_token_audience", or separate words such as "access token
// audience". Each scalar takes exactly one nonempty value. Lists take one or more
// values. Delay/retry integers are seconds or counts as specified by oauth.Config.
// Switches use enabled/disabled keywords, e.g. "nonce enabled", "pkce enabled",
// "tls verification enabled", and "metadata discovery disabled". Boolean
// literals and underscore switch names are rejected. Each setting occurs once;
// spelling aliases and opposite states configure the same setting.
//
// "jwks key <kid> <path>" accepts a public PEM file and may repeat with distinct
// key IDs. "login icon <attribute> <value>" configures appearance; attributes are
// class name, color, background color, text, text color, text background color,
// and priority. Encode each keyword separately and preserve quoted value tokens.
// Reject empty arguments before encoding: EncodeArgs can trim a trailing empty
// field, which this parser cannot recover. Multiline records are rejected.
//
// oauth.Config.Validate owns defaults and semantic checks, including reading
// configured static public-key files. This function performs no discovery,
// network access, credential generation, or runtime startup. It returns a fresh
// normalized config without mutating inputs, or nil and an error without input
// values. ServerName is derived; the unused AppSecret and UserRoleMapList fields
// are not operator settings. Typed-only settings such as LogoutURL remain subject
// to the separate shared identity-provider parameter allowlist when adapted.
func NewOAuthIdentityProviderConfigFromDirectives(name string, statements []string) (*oauth.Config, error) {
	if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\r\n\x00") {
		return nil, fmt.Errorf("invalid OAuth identity provider name")
	}
	config := &oauth.Config{Name: name}
	fields := newOAuthFields(config)
	seen := make(map[string]bool)
	for i, statement := range statements {
		line := i + 1
		// DecodeArgs reads only one CSV record; reject ignored trailing records.
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid OAuth identity provider directive at line %d", line)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 || slices.Contains(args, "") {
			return nil, fmt.Errorf("invalid OAuth identity provider directive at line %d", line)
		}
		if args[0] == "jwks" {
			if len(args) != 4 || args[1] != "key" || strings.TrimSpace(args[2]) == "" || strings.TrimSpace(args[3]) == "" {
				return nil, fmt.Errorf("expected jwks key with one ID and path at line %d", line)
			}
			if config.JwksKeys == nil {
				config.JwksKeys = make(map[string]string)
			}
			if _, exists := config.JwksKeys[args[2]]; exists {
				return nil, fmt.Errorf("duplicate OAuth JWKS key ID at line %d", line)
			}
			config.JwksKeys[args[2]] = args[3]
			continue
		}
		if len(args) >= 2 && args[0] == "login" && args[1] == "icon" {
			if config.LoginIcon == nil {
				config.LoginIcon = &icons.LoginIcon{}
			}
			key, field, values := matchField(args[2:], newLoginIconFields(config.LoginIcon))
			if field == nil {
				return nil, fmt.Errorf("unsupported OAuth login icon directive at line %d", line)
			}
			if err := applyField("login icon "+key, field, values, seen, line); err != nil {
				return nil, err
			}
			continue
		}
		key, field, values := matchField(args, fields)
		if field == nil {
			return nil, fmt.Errorf("unsupported OAuth identity provider directive at line %d", line)
		}
		if err := applyField(key, field, values, seen, line); err != nil {
			return nil, err
		}
	}
	if err := config.Validate(); err != nil {
		// Domain errors can contain URLs, key paths, and other supplied values.
		return nil, fmt.Errorf("invalid OAuth identity provider configuration")
	}
	return config, nil
}
