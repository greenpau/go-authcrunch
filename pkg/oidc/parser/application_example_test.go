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

func ExampleNewOAuthApplicationConfigFromDirectives() {
	body := []string{
		cfgutil.EncodeArgs([]string{"redirect_uri", "https://app.example.com/callback"}),
		cfgutil.EncodeArgs([]string{"redirect_uri", "https://app.example.com/other/callback"}),
	}
	// Provision once. Store this registration privately before using the provider;
	// a later adaptation loads it from the embedding application's secret store.
	client, err := oidcparser.NewOIDCClientConfigFromDirectives("website", body)
	if err != nil {
		panic(err)
	}
	persisted, err := oidc.NewOAuthApplicationConfig("website", client)
	if err != nil {
		panic(err)
	}
	header := cfgutil.EncodeArgs([]string{"oauth", "application", "website"})
	application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(header, body, persisted)
	if err != nil {
		panic(err)
	}
	fmt.Println(application.Name)
	fmt.Println("same credentials:", application.Client.ClientID == client.ClientID && application.Client.ClientSecret == client.ClientSecret)
	fmt.Println(application.Client.TokenEndpointAuthMethod)
	// Output:
	// website
	// same credentials: true
	// client_secret_basic
}
