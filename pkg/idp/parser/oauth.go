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

// Package parser adapts provider-specific directive parsers to the shared
// identity-provider configuration API.
package parser

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/idp"
	oauthparser "github.com/greenpau/go-authcrunch/pkg/idp/oauth/parser"
)

// NewOAuthIdentityProviderConfigFromDirectives parses an upstream OAuth provider
// block body using oauth/parser.NewOAuthIdentityProviderConfigFromDirectives and
// returns configuration for the shared identity-provider dispatcher. Pass the
// provider name separately and body statements encoded with cfgutil.EncodeArgs;
// no header or braces. The OAuth parser owns the complete grammar and validation.
//
// The adapter preserves normalized settings, including explicit issuer and
// access_token_audience values. Name belongs to the shared config envelope and
// ServerName is runtime-derived; neither is placed in Params. The shared config
// allowlist remains authoritative: typed-only fields such as logout_url are
// rejected rather than silently discarded. No input is mutated and no partial
// result or input values are returned on error. No runtime provider is started.
func NewOAuthIdentityProviderConfigFromDirectives(name string, statements []string) (*idp.IdentityProviderConfig, error) {
	config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives(name, statements)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("could not encode OAuth identity provider configuration")
	}
	var params map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	// Preserve integral retry/delay values exactly across the shared map API.
	decoder.UseNumber()
	if err := decoder.Decode(&params); err != nil {
		return nil, fmt.Errorf("could not adapt OAuth identity provider configuration")
	}
	delete(params, "name")
	delete(params, "server_name")
	provider, err := idp.NewIdentityProviderConfig(config.Name, "oauth", params)
	if err != nil {
		return nil, fmt.Errorf("OAuth configuration is not supported by shared identity provider configuration")
	}
	return provider, nil
}
