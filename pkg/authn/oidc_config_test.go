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

package authn_test

import (
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func TestPortalConfigConfigureOIDCProvider(t *testing.T) {
	provider := &oidc.Config{Enabled: true, Issuer: "https://auth.example.test/auth", Realms: []string{"local"}, SigningKeyFiles: []string{"private.pem"}, Clients: []*oidc.ClientConfig{{ClientID: "public", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://app.example.test/callback"}}}}
	if err := (*authn.PortalConfig)(nil).ConfigureOIDCProvider(provider); err == nil {
		t.Fatal("nil portal accepted")
	}
	portal := &authn.PortalConfig{Name: "web"}
	for _, invalid := range []*oidc.Config{nil, {Enabled: true}, {Clients: []*oidc.ClientConfig{nil}}} {
		if err := portal.ConfigureOIDCProvider(invalid); err == nil || portal.OIDCProvider != nil {
			t.Fatal("invalid provider changed portal")
		}
	}
	if err := portal.ConfigureOIDCProvider(provider); err != nil {
		t.Fatal(err)
	}
	if provider.TokenLifetimeSeconds != 0 || provider.Clients[0].Scopes != nil {
		t.Fatal("validation mutated caller provider")
	}
	provider.Realms[0] = "changed"
	provider.SigningKeyFiles[0] = "changed"
	provider.Clients[0].RedirectURIs[0] = "changed"
	if portal.OIDCProvider.Realms[0] != "local" || portal.OIDCProvider.SigningKeyFiles[0] != "private.pem" || portal.OIDCProvider.Clients[0].RedirectURIs[0] != "https://app.example.test/callback" {
		t.Fatal("portal did not snapshot configuration")
	}
	if err := portal.ConfigureOIDCProvider(&oidc.Config{}); err == nil || !portal.OIDCProvider.Enabled {
		t.Fatal("second definition replaced provider")
	}
}
