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
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestOIDCProviderDirectiveConfigurationDispatch(t *testing.T) {
	for _, tc := range []struct{ name, issuer, realm, key, state, wantError string }{
		{name: "enabled defaults"},
		{name: "disabled", state: "disabled"},
		{name: "reserved portal mount", issuer: "https://auth.example.test/api/identity", wantError: "reserved portal route"},
		{name: "missing local realm", realm: "missing", wantError: "exactly one local store"},
		{name: "missing key file", key: "testdata/oidc-nonexistent.pem", wantError: "oidc signing key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, realm, key := tc.issuer, tc.realm, tc.key
			if issuer == "" {
				issuer = "https://auth.example.test/auth"
			}
			if realm == "" {
				realm = "local"
			}
			if key == "" {
				key = "testdata/rskeys/test_2_pri.pem"
			}
			statements := []string{
				cfgutil.EncodeArgs([]string{"issuer", issuer}),
				cfgutil.EncodeArgs([]string{"realms", realm}),
				cfgutil.EncodeArgs([]string{"signing", "key", "files", key}),
				"applications desktop",
			}
			if tc.state != "" {
				statements = append(statements, tc.state)
			}
			registration, err := oidcparser.NewOIDCClientConfigFromDirectives("desktop", []string{
				"client_id desktop-client", "token_endpoint_auth_method none", "redirect_uri http://127.0.0.1:8400/callback",
			})
			if err != nil {
				t.Fatal(err)
			}
			providerConfig, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, map[string]*oidc.ClientConfig{"desktop": registration})
			if err != nil {
				t.Fatal(err)
			}
			config := &authcrunch.Config{
				IdentityStores:        []*ids.IdentityStoreConfig{{Name: "local-store", Kind: "local", Params: map[string]any{"realm": "local", "path": filepath.Join(t.TempDir(), "users.json")}}},
				AuthenticationPortals: []*authn.PortalConfig{{Name: "oidc", IdentityStores: []string{"local-store"}, OIDCProvider: providerConfig}},
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var restored authcrunch.Config
			if err := json.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			server, err := authcrunch.NewServer(&restored, zap.NewNop())
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("construction error = %v; expected %s", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			portal, err := server.GetPortalByName("oidc")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(portal.Close)
			provider := portal.GetOIDCProvider()
			if tc.state == "disabled" {
				if provider != nil {
					t.Fatal("disabled directives created a provider")
				}
				return
			}
			if provider == nil || !provider.SupportsRealm("local") || provider.SupportsRealm("missing") || provider.Discovery()["issuer"] != issuer {
				t.Fatal("parsed provider was not connected to the portal")
			}
			if restored.AuthenticationPortals[0].OIDCProvider.TokenLifetimeSeconds != 300 || restored.AuthenticationPortals[0].CookieConfig == nil || restored.AuthenticationPortals[0].API == nil {
				t.Fatal("parsed configuration bypassed portal defaults")
			}
		})
	}
}
