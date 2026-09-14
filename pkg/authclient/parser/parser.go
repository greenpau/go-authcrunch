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

// Package parser decodes reusable authentication-client configuration directives.
package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewAuthenticationClientConfigFromDirectives parses a block body encoded one
// statement at a time with cfgutil.EncodeArgs. Hosts own tokenization and
// placeholder expansion. The grammar is "<setting> <value>": base url, username,
// realm, password, api key, totp secret, totp code length, totp code lifetime
// (seconds), access token name, and refresh transport (cookie or body).
// Each setting occurs once. No enclosing header or braces are accepted.
//
// An empty block fails Config.Validate's required identity/URL checks. Omitted
// refresh transport preserves cookie mode; body explicitly requests native
// credentials and requires the portal opt-in. API keys remain access-only.
// Defaults and semantic checks belong to Config.Validate. This function reads
// no files, contacts no portal, and never mutates the caller's statements.
//
// Reject empty tokens before encoding: EncodeArgs may trim a trailing empty
// field. Unknown, duplicate, malformed, multiline, empty, and invalid settings
// return nil and a redacted error without raw statements or credential values.
func NewAuthenticationClientConfigFromDirectives(statements []string) (*authclient.Config, error) {
	config := &authclient.Config{}
	stringsByKey := map[string]*string{
		"base url":          &config.BaseURL,
		"username":          &config.Username,
		"realm":             &config.Realm,
		"password":          &config.Password,
		"api key":           &config.APIKey,
		"totp secret":       &config.TOTPSecret,
		"access token name": &config.AccessTokenName,
		"refresh transport": &config.RefreshTransport,
	}
	integersByKey := map[string]*int{
		"totp code length":   &config.TOTPCodeLength,
		"totp code lifetime": &config.TOTPCodeLifetime,
	}
	seen := make(map[string]bool)
	for i, statement := range statements {
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid authentication client directive at line %d", i+1)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return nil, fmt.Errorf("invalid authentication client directive at line %d", i+1)
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return nil, fmt.Errorf("empty authentication client argument at line %d", i+1)
			}
		}
		keywords, value := args[:len(args)-1], args[len(args)-1]
		key := strings.Join(keywords, " ")
		if !slices.Equal(strings.Split(key, " "), keywords) || seen[key] {
			return nil, fmt.Errorf("invalid or duplicate authentication client setting at line %d", i+1)
		}
		seen[key] = true
		if field := stringsByKey[key]; field != nil {
			*field = value
		} else if field := integersByKey[key]; field != nil {
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid authentication client number at line %d", i+1)
			}
			*field = n
		} else {
			return nil, fmt.Errorf("unknown authentication client setting at line %d", i+1)
		}
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid authentication client configuration: %w", err)
	}
	return config, nil
}
