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
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewOAuthApplicationConfigFromDirectives recognizes an encoded
// "oauth application <nickname>" header and adapts its body using the existing
// OIDC client field parser. Encode the header and each statement separately with
// cfgutil.EncodeArgs; pass no braces. The embedding adapter owns block traversal
// and placeholder expansion. Unknown headers and malformed bodies fail closed.
// Repeat redirect_uri with exactly one callback per statement; the plural
// redirect_uris directive is unsupported. request_object_key is also repeatable;
// other fields occur at most once. Request Object verification keys and signing
// algorithm policy come from directives, never inherited persisted policy.
//
// Adaptation never generates credentials. Supply explicit client_id and, for a
// confidential client, client_secret, or provide a persisted registration with
// the same nickname. Only omitted credentials are inherited; current directives
// define all other settings. Changing the client ID requires an explicit secret.
// A public client never inherits a secret. An explicit secret rotates it.
//
// For initial provisioning, use NewOIDCClientConfigFromDirectives or
// oidc.NewClientConfig, wrap it with oidc.NewOAuthApplicationConfig, and persist
// that registration before adapting or serving it. Restore the registration from
// trusted, private storage on reload. Missing storage must not silently create a
// new client identity. This function performs no IO and never mutates inputs;
// concurrent calls can share immutable inputs. Errors do not include raw values.
func NewOAuthApplicationConfigFromDirectives(header string, statements []string, persisted *oidc.OAuthApplicationConfig) (*oidc.OAuthApplicationConfig, error) {
	if strings.ContainsAny(header, "\r\n") {
		return nil, fmt.Errorf("invalid oauth application header")
	}
	args, err := cfgutil.DecodeArgs(header)
	if err != nil || len(args) != 3 || args[0] != "oauth" || args[1] != "application" {
		return nil, fmt.Errorf("expected oauth application header with one nickname")
	}
	client, err := parseOIDCClientConfigFromDirectives(args[2], statements)
	if err != nil {
		return nil, err
	}
	if persisted != nil {
		previous, err := oidc.NewOAuthApplicationConfig(persisted.Name, persisted.Client)
		if err != nil {
			return nil, fmt.Errorf("invalid persisted oauth application: %w", err)
		}
		if previous.Name != args[2] {
			return nil, fmt.Errorf("persisted oauth application nickname does not match")
		}
		if client.ClientID == "" {
			client.ClientID = previous.Client.ClientID
		}
		if client.ClientSecret == "" && client.TokenEndpointAuthMethod != "none" && client.ClientID == previous.Client.ClientID {
			client.ClientSecret = previous.Client.ClientSecret
		}
	}
	if client.ClientID == "" {
		return nil, fmt.Errorf("oauth application requires an explicit or persisted client_id")
	}
	if client.ClientSecret == "" && (client.TokenEndpointAuthMethod == "" || client.TokenEndpointAuthMethod == "client_secret_basic" || client.TokenEndpointAuthMethod == "client_secret_post") {
		return nil, fmt.Errorf("oauth application requires an explicit or persisted client_secret")
	}
	return oidc.NewOAuthApplicationConfig(args[2], client)
}
