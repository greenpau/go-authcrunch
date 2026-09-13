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

package oidc_test

import (
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func ExampleNewClientConfig() {
	client, err := oidc.NewClientConfig(oidc.ClientConfig{
		ClientName:   "My application",
		RedirectURIs: []string{"https://app.example.com/oidc/callback"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Persist client securely and deliver ClientID and ClientSecret to the app.
	// Only non-sensitive configuration is printed in this example.
	fmt.Println(client.ClientName)
	fmt.Println(client.TokenEndpointAuthMethod, client.RequirePKCE)
	fmt.Println(client.Scopes)
	// Output:
	// My application
	// client_secret_basic true
	// [openid profile email]
}

func ExampleConfig_AddClient() {
	client, err := oidc.NewClientConfig(oidc.ClientConfig{
		ClientName:              "Desktop application",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://127.0.0.1:8400/callback"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	config := &oidc.Config{
		Enabled:         true,
		Issuer:          "https://auth.example.com/auth",
		Realms:          []string{"local"},
		SigningKeyFiles: []string{"/etc/authcrunch/oidc-signing.pem"},
	}
	if err := config.AddClient(client); err != nil {
		fmt.Println(err)
		return
	}
	// Persist config before assigning it to authn.PortalConfig.OIDCProvider or
	// passing it to oidc.NewProvider with the host's IdentityVerifier.
	fmt.Println(len(config.Clients), client.RequirePKCE, client.ClientSecret == "")
	// Output: 1 true true
}
