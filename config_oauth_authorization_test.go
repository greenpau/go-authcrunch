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
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"go.uber.org/zap"
)

func TestConfigOAuthAuthorizationReferences(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*authcrunch.Config)
	}{
		{"missing", func(c *authcrunch.Config) { c.IdentityProviders = nil }},
		{"wrong kind", func(c *authcrunch.Config) { c.IdentityProviders[0].Kind = "saml" }},
		{"duplicate provider", func(c *authcrunch.Config) { c.IdentityProviders = append(c.IdentityProviders, c.IdentityProviders[0]) }},
		{"disabled provider", func(c *authcrunch.Config) { c.AddDisabledIdentityProvider("company") }},
		{"JWT bearer validation", func(c *authcrunch.Config) { c.AuthorizationPolicies[0].ValidateBearerHeader = true }},
		{"typed JWT keys", func(c *authcrunch.Config) {
			c.AuthorizationPolicies[0].CryptoKeyStoreConfig = &kms.CryptoKeyStoreConfig{TokenName: "access_token"}
		}},
		{"nil policy", func(c *authcrunch.Config) { c.AuthorizationPolicies = append(c.AuthorizationPolicies, nil) }},
		{"cookie collision", func(c *authcrunch.Config) {
			c.AuthorizationPolicies[1].OAuth.SessionCookieName = "AUTHZ_primary_SESSION"
		}},
		{"cross role cookie collision", func(c *authcrunch.Config) { c.AuthorizationPolicies[1].OAuth.LoginCookieName = "AUTHZ_primary_SESSION" }},
		{"callback collision", func(c *authcrunch.Config) { c.AuthorizationPolicies[1].OAuth.BasePath = "/_authcrunch/oauth2/primary" }},
		{"nested callback collision", func(c *authcrunch.Config) {
			c.AuthorizationPolicies[1].OAuth.BasePath = "/_authcrunch/oauth2/primary/child"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &authcrunch.Config{IdentityProviders: []*idp.IdentityProviderConfig{{Name: "company", Kind: "oauth"}}}
			for _, name := range []string{"primary", "secondary"} {
				cfg.AuthorizationPolicies = append(cfg.AuthorizationPolicies, &authz.PolicyConfig{Name: name, OAuth: &authz.OAuthAuthorizationConfig{IdentityProvider: "company"}, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}})
			}
			tc.change(cfg)
			// Invalid references fail before the deliberately unprovisioned provider is
			// built or any discovery request can run.
			if cfg.Validate() == nil {
				t.Fatal("invalid policy graph accepted")
			}
			if runtime, err := authcrunch.NewServer(cfg, zap.NewNop()); err == nil {
				runtime.Close()
				t.Fatal("invalid policy graph started")
			}
		})
	}
}
