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

package authn

import (
	"slices"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

func TestGithubTransformProviderBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, driver, realm, method string
		unknown, noFactory, want    bool
	}{
		{name: "GitHub arbitrary realm", driver: "github", realm: "engineering", method: "oauth2", want: true},
		{name: "GitHub no transforms", driver: "github", realm: "engineering", method: "oauth2", noFactory: true, want: true},
		{name: "non-GitHub named github", driver: "generic", realm: "github", method: "oauth2"},
		{name: "non-GitHub no transforms", driver: "generic", realm: "github", method: "oauth2", noFactory: true},
		{name: "local", driver: "github", realm: "github", method: "local"},
		{name: "unknown realm", driver: "github", realm: "github", method: "oauth2", unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := oauth.NewIdentityProvider(&oauth.Config{
				Name: "upstream", Realm: tc.realm, Driver: tc.driver,
				ClientID: "fixture", ClientSecret: "synthetic-secret",
				BaseAuthURL: "https://identity.example/", MetadataURL: "https://identity.example/metadata",
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			cfg, err := transformparser.NewUserTransformerConfigFromDirectives([]string{
				"match github id exact 123", "match github org exact acme", "add role member",
			})
			if err != nil {
				t.Fatal(err)
			}
			factory, err := transformer.NewFactory([]*transformer.Config{cfg})
			if err != nil {
				t.Fatal(err)
			}
			p := &Portal{identityProviders: []idp.IdentityProvider{provider}, transformer: factory, logger: zap.NewNop()}
			if tc.noFactory {
				p.transformer = nil
			}
			rr := requests.NewRequest()
			rr.Upstream.Realm, rr.Upstream.Method = tc.realm, tc.method
			if tc.unknown {
				rr.Upstream.Realm = "unknown"
			}
			claims := map[string]any{"github_id": "123", "github_orgs": []string{"acme"}, "origin": "github", "realm": "github"}
			if err := p.transformUser(t.Context(), rr, claims); err != nil {
				t.Fatal(err)
			}
			_, hasID := claims["github_id"]
			_, hasOrgs := claims["github_orgs"]
			if hasID != tc.want || hasOrgs != tc.want {
				t.Fatal("provider claim boundary failed")
			}
			roles, _ := claims["roles"].([]string)
			if slices.Contains(roles, "member") != (tc.want && !tc.noFactory) {
				t.Fatal("untrusted provider matched")
			}
		})
	}
}
