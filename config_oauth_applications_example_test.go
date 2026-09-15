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

package authcrunch_test

import (
	"fmt"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func ExampleConfig_ConfigureOIDCProvider() {
	config := authcrunch.NewConfig()
	application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(
		cfgutil.EncodeArgs([]string{"oauth", "application", "desktop"}), []string{
			"client_id desktop-client", "token_endpoint_auth_method none",
			"redirect_uri http://127.0.0.1:8400/callback",
		}, nil)
	if err != nil {
		panic(err)
	}
	if err := config.AddOAuthApplication(application); err != nil {
		panic(err)
	}
	portal := &authn.PortalConfig{Name: "portal", IdentityStores: []string{"local-store"}}
	// Collect every application block before configuring providers, regardless
	// of block order. The parser resolves the nickname to its registered client.
	if err := config.ConfigureOIDCProvider(portal, []string{
		"issuer https://auth.example.com/auth", "realms local",
		"signing key files /etc/auth/oidc.pem", "applications desktop",
	}); err != nil {
		panic(err)
	}
	if err := config.AddAuthenticationPortal(portal); err != nil {
		panic(err)
	}
	// Configure local-store, then pass config to authcrunch.NewServer.
	fmt.Println(portal.OIDCProvider.Clients[0].ClientID)
	fmt.Println(portal.OIDCProvider.Issuer)
	// Output:
	// desktop-client
	// https://auth.example.com/auth
}
