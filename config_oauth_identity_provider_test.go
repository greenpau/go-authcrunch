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
	"encoding/json"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestConfigOAuthIdentityProviderDirectives(t *testing.T) {
	provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("corporate", []string{
		"realm employees", "driver generic", "client_id portal", "client_secret synthetic-test-secret",
		"metadata_url https://idp.example/discovery", "issuer https://Issuer.example/",
		cfgutil.EncodeArgs([]string{"access_token_audience", "resource with spaces"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	config := authcrunch.NewConfig()
	if err := config.AddIdentityProvider(provider.Name, provider.Kind, provider.Params); err != nil {
		t.Fatal(err)
	}
	if err := config.AddAuthenticationPortal(&authn.PortalConfig{Name: "portal", IdentityProviders: []string{provider.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored authcrunch.Config
	if err := json.Unmarshal(encoded, &restored); err != nil || restored.Validate() != nil || len(restored.IdentityProviders) != 1 {
		t.Fatal("root configuration could not reload the parsed identity provider")
	}
	params := restored.IdentityProviders[0].Params
	if params["issuer"] != "https://Issuer.example/" || params["access_token_audience"] != "resource with spaces" {
		t.Fatal("root configuration changed the provider's explicit trust settings")
	}
}
