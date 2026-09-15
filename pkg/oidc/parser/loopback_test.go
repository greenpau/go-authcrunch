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
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestOIDCNativeLoopbackRegistration(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/callback?q=a%20b", "http://[::1]:1/callback?", "http://127.0.0.1:65535/c%61llback"} {
		t.Run(raw, func(t *testing.T) {
			statements := []string{"client_id native", "token_endpoint_auth_method none", cfgutil.EncodeArgs([]string{"redirect_uri", raw})}
			original := slices.Clone(statements)
			client, err := oidcparser.NewOIDCClientConfigFromDirectives("desktop", statements)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			var restored oidc.ClientConfig
			if json.Unmarshal(encoded, &restored) != nil || restored.Validate() != nil {
				t.Fatal("native registration could not be restored")
			}
			if !reflect.DeepEqual(client, &restored) || !slices.Equal(statements, original) || restored.TokenEndpointAuthMethod != "none" || !restored.RequirePKCE || restored.ClientSecret != "" || !slices.Equal(restored.RedirectURIs, []string{raw}) {
				t.Fatal("registration/persistence changed native policy or raw redirect")
			}
		})
	}
	for _, raw := range []string{"http://127.0.0.1:/callback", "http://127.0.0.1:0/callback", "http://[::1]:65536/callback", "http://127.0.0.1:abc/callback", "http://localhost:43111/callback", "http://[::1%25zone]:43111/callback", "http://user@127.0.0.1:43111/callback", "http://127.0.0.1:43111/callback#"} {
		t.Run(raw, func(t *testing.T) {
			client, err := oidcparser.NewOIDCClientConfigFromDirectives("desktop", []string{"token_endpoint_auth_method none", cfgutil.EncodeArgs([]string{"redirect_uri", raw})})
			if err == nil || client != nil {
				t.Fatal("invalid callback registration returned a partial client")
			}
		})
	}
}

func ExampleNewOIDCClientConfigFromDirectives_loopback() {
	client, err := oidcparser.NewOIDCClientConfigFromDirectives("Desktop app", []string{
		"client_id desktop", "token_endpoint_auth_method none",
		"redirect_uri http://127.0.0.1/callback",
		"redirect_uri http://[::1]/callback",
	})
	if err != nil {
		panic(err)
	}
	// Bind a local ephemeral listener, then use its port in authorization. Keep
	// that actual URI unchanged for the subsequent PKCE token exchange.
	fmt.Println(client.ClientID, client.TokenEndpointAuthMethod, client.RequirePKCE)
	fmt.Println(client.RedirectURIs)
	// Output:
	// desktop none true
	// [http://127.0.0.1/callback http://[::1]/callback]
}
