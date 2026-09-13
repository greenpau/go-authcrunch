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

	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

func ExampleNewOIDCClientConfigFromDirectives() {
	client, err := oidcparser.NewOIDCClientConfigFromDirectives("myapp", []string{
		"client_id myapp",
		`client_name "My application"`,
		"redirect_uris https://app.example.com/oidc/callback https://app.example.com/other/callback",
		"scopes openid profile email",
		"require_pkce yes",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Initial provisioning generated the omitted secret. Persist the result
	// before using it in the provider or adapting the directives again.
	fmt.Println(client.ClientID, client.ClientName)
	fmt.Println(len(client.RedirectURIs), client.RequirePKCE)
	// Output:
	// myapp My application
	// 2 true
}
