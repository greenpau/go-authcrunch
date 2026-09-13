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
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func providerDirectives(extra ...string) []string {
	return append([]string{
		"realm employees", "driver generic", "client_id portal", "client_secret synthetic-test-secret",
		"base_auth_url https://endpoint.example/", "metadata_url https://metadata.example/discovery",
	}, extra...)
}

func TestNewOAuthIdentityProviderConfigFromDirectives(t *testing.T) {
	input := providerDirectives("issuer https://Issuer.example/", `access_token_audience "resource with spaces"`, "delay start 3", "scopes openid custom", "nonce enabled")
	original := slices.Clone(input)
	for range 2 {
		config, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("corporate", input)
		if err != nil {
			t.Fatal(err)
		}
		if config.Name != "corporate" || config.Kind != "oauth" || config.Params["issuer"] != "https://Issuer.example/" || config.Params["access_token_audience"] != "resource with spaces" {
			t.Fatal("shared configuration lost provider identity or trust settings")
		}
		for _, field := range []string{"name", "server_name"} {
			if _, exists := config.Params[field]; exists {
				t.Fatal("shared params contain an envelope or derived field")
			}
		}
		if err := config.Validate(); err != nil {
			t.Fatal("shared dispatcher rejected parsed configuration")
		}
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		var restored idp.IdentityProviderConfig
		if err := json.Unmarshal(encoded, &restored); err != nil || restored.Validate() != nil || restored.Params["issuer"] != config.Params["issuer"] || restored.Params["access_token_audience"] != config.Params["access_token_audience"] {
			t.Fatal("shared configuration did not survive consumer JSON persistence")
		}
		// Verify defaults supplied by the typed validator are carried into Params.
		params, err := json.Marshal(config.Params)
		if err != nil {
			t.Fatal(err)
		}
		var typed oauth.Config
		if err := json.Unmarshal(params, &typed); err != nil || typed.RetryAttempts != 2 || typed.RetryInterval != 3 || typed.NonceDisabled || !slices.Equal(typed.Scopes, []string{"openid", "custom"}) {
			t.Fatal("shared adaptation lost typed defaults or controls")
		}
		config.Params["issuer"] = "changed"
		config.Params["scopes"].([]any)[0] = "changed"
	}
	if !slices.Equal(input, original) {
		t.Fatal("adaptation mutated input directives")
	}
}

func TestOAuthIdentityProviderAdapterPreservesIntegers(t *testing.T) {
	// A float64 intermediate would round this representable int on 64-bit hosts.
	value := int64(1<<53 + 1)
	if strconv.IntSize == 32 {
		value = 1<<31 - 1
	}
	config, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", providerDirectives("retry_interval "+strconv.FormatInt(value, 10)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config.Params)
	if err != nil {
		t.Fatal(err)
	}
	var typed oauth.Config
	if err := json.Unmarshal(encoded, &typed); err != nil || int64(typed.RetryInterval) != value {
		t.Fatal("shared adapter changed an integer during conversion")
	}
}

func TestOAuthIdentityProviderAdapterRejections(t *testing.T) {
	for _, tc := range []struct {
		name, provider string
		statements     []string
	}{
		{"empty name", "", providerDirectives()},
		{"missing settings", "upstream", nil},
		{"malformed issuer", "upstream", providerDirectives("issuer sensitive-one sensitive-two")},
		{"duplicate audience", "upstream", providerDirectives("access_token_audience one", "access token audience two")},
		{"unsupported field", "upstream", providerDirectives("unsupported_field sensitive-value")},
		{"typed-only setting", "upstream", providerDirectives("logout url https://sensitive-value.example/logout")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives(tc.provider, tc.statements)
			if got != nil || err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("invalid or unsupported input must fail without partial results or values")
			}
		})
	}
}

func ExampleNewOAuthIdentityProviderConfigFromDirectives() {
	config, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("corporate", []string{
		"realm employees", "driver generic", "client_id portal", "client_secret synthetic-example-secret",
		cfgutil.EncodeArgs([]string{"metadata_url", "https://idp.example/.well-known/openid-configuration"}),
		cfgutil.EncodeArgs([]string{"issuer", "https://idp.example"}),
		cfgutil.EncodeArgs([]string{"access_token_audience", "resource-api"}),
	})
	if err != nil {
		panic(err)
	}
	// Pass config to idp.NewIdentityProvider, or its Name, Kind, and Params to
	// authcrunch.Config.AddIdentityProvider when assembling a complete server.
	fmt.Println(config.Name, config.Kind, config.Params["issuer"], config.Params["access_token_audience"])
	// Output: corporate oauth https://idp.example resource-api
}
