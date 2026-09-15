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

package parser_test

import (
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func ExampleNewOIDCProviderConfigFromDirectives() {
	application, err := oidcparser.NewOIDCClientConfigFromDirectives("desktop", []string{
		"client_id desktop-app",
		"token_endpoint_auth_method none",
		"redirect_uri http://127.0.0.1:8400/callback",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Collect registrations before parsing provider settings, regardless of
	// where their blocks occur in the embedding application's configuration.
	applications := map[string]*oidc.ClientConfig{"desktop": application}
	config, err := oidcparser.NewOIDCProviderConfigFromDirectives([]string{
		"issuer https://auth.example.com/auth",
		"realms local",
		cfgutil.EncodeArgs([]string{"signing", "key", "files", "/etc/auth/oidc signing.pem"}),
		"applications desktop",
		"token lifetime 120",
		"max sessions 500",
	}, applications)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Assign config to authn.PortalConfig.OIDCProvider or pass it to
	// oidc.NewProvider with the embedding application's IdentityVerifier.
	fmt.Println(config.Enabled, config.Issuer)
	fmt.Println(config.Clients[0].ClientID, config.Clients[0].RequirePKCE)
	fmt.Println(config.TokenLifetimeSeconds, config.MaxSessions)
	// Output:
	// true https://auth.example.com/auth
	// desktop-app true
	// 120 500
}
