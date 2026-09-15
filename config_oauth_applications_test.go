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
	"encoding/xml"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

func oauthApplicationTestConfig(t *testing.T) *oidc.OAuthApplicationConfig {
	t.Helper()
	application, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", []string{
		"client_id protocol-id", "client_secret " + strings.Repeat("s", 32), "redirect_uri https://app.example.test/callback",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func TestConfigOAuthApplications(t *testing.T) {
	config := authcrunch.NewConfig()
	application := oauthApplicationTestConfig(t)
	if err := config.AddOAuthApplication(application); err != nil {
		t.Fatal(err)
	}
	if err := config.AddOAuthApplication(application); err == nil {
		t.Fatal("duplicate definition accepted")
	}
	application.Name = "changed"
	application.Client.RedirectURIs[0] = "https://changed.example.test/"
	found, err := config.GetOAuthApplication("web")
	if err != nil {
		t.Fatal(err)
	}
	if found.Client.RedirectURIs[0] != "https://app.example.test/callback" {
		t.Fatal("registration did not copy inputs")
	}
	found.Client.ClientSecret = "changed"
	found.Client.Scopes[0] = "changed"
	all, err := config.GetOAuthApplications()
	if err != nil {
		t.Fatal(err)
	}
	if all["web"].ClientSecret != strings.Repeat("s", 32) || all["web"].Scopes[0] != "openid" {
		t.Fatal("lookup exposed mutable registration")
	}
	all["web"].RedirectURIs[0] = "changed"
	delete(all, "web")
	for _, name := range []string{"missing", "protocol-id", "Web"} {
		if result, err := config.GetOAuthApplication(name); result != nil || err == nil {
			t.Fatal("lookup did not use exact nickname")
		}
	}
	var readers sync.WaitGroup
	for range 16 {
		readers.Go(func() {
			result, err := config.GetOAuthApplication("web")
			if err != nil {
				t.Error(err)
				return
			}
			if result.Client.RedirectURIs[0] != "https://app.example.test/callback" {
				t.Error("lookup mutated registry")
			}
			result.Client.Scopes[0] = "changed"
		})
	}
	readers.Wait()
}

func TestConfigOAuthApplicationSerialization(t *testing.T) {
	config := &authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{oauthApplicationTestConfig(t)}}
	for _, format := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"json", json.Marshal, json.Unmarshal}, {"xml", xml.Marshal, xml.Unmarshal}, {"yaml", yaml.Marshal, yaml.Unmarshal},
	} {
		t.Run(format.name, func(t *testing.T) {
			data, err := format.marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var restored authcrunch.Config
			if err := format.unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			previous, err := restored.GetOAuthApplication("web")
			if err != nil {
				t.Fatal(err)
			}
			adapted, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", []string{"redirect_uri https://app.example.test/callback"}, previous)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(adapted, config.OAuthApplications[0]) {
				t.Fatal("persisted registration changed during re-adaptation")
			}
		})
	}
}

func TestConfigOAuthApplicationValidation(t *testing.T) {
	valid := oauthApplicationTestConfig(t)
	for _, tc := range []struct {
		name   string
		config *authcrunch.Config
		want   string
	}{
		{"nil config", nil, "config is nil"},
		{"nil entry", &authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{nil}}, "is nil"},
		{"nil client", &authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{{Name: "web"}}}, "client is nil"},
		{"invalid name", &authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{{Client: valid.Client}}}, "nickname"},
		{"missing credentials", &authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{{Name: "web", Client: &oidc.ClientConfig{}}}}, "client_id"},
		{"duplicates", &authcrunch.Config{OAuthApplications: []*oidc.OAuthApplicationConfig{valid, valid}}, "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if result, err := tc.config.GetOAuthApplications(); result != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("registry error = %v", err)
			}
			if result, err := tc.config.GetOAuthApplication("web"); result != nil || err == nil {
				t.Fatal("lookup accepted invalid registry")
			}
			if err := tc.config.AddOAuthApplication(valid); err == nil {
				t.Fatal("add accepted invalid registry")
			}
			if err := tc.config.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error = %v", err)
			}
			portal := &authn.PortalConfig{Name: "web"}
			if err := tc.config.ConfigureOIDCProvider(portal, []string{"disabled"}); err == nil || portal.OIDCProvider != nil {
				t.Fatal("provider accepted invalid registry")
			}
		})
	}
	for _, entry := range []*oidc.OAuthApplicationConfig{nil, {}, {Name: "web"}} {
		config := authcrunch.NewConfig()
		if err := config.AddOAuthApplication(entry); err == nil || len(config.OAuthApplications) != 0 {
			t.Fatal("failed add changed registry")
		}
	}
}

func TestConfigConfigureOIDCProvider(t *testing.T) {
	config := authcrunch.NewConfig()
	// An adapter can encounter the provider first and defer this body until all
	// application blocks have been registered. No outer-server parser is needed.
	body := []string{"issuer https://auth.example.test/auth", "realms local", "signing key files private.pem", "applications web"}
	if err := config.AddOAuthApplication(oauthApplicationTestConfig(t)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "second"} {
		portal := &authn.PortalConfig{Name: name}
		// Configure after early portal validation must restore OIDC defaults.
		if err := portal.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := config.ConfigureOIDCProvider(portal, body); err != nil {
			t.Fatal(err)
		}
		if err := config.AddAuthenticationPortal(portal); err != nil {
			t.Fatal(err)
		}
		if portal.API == nil || portal.CookieConfig == nil || len(portal.OIDCProvider.Clients) != 1 || portal.OIDCProvider.Clients[0].ClientID != "protocol-id" {
			t.Fatal("provider or portal defaults missing")
		}
		before := portal.OIDCProvider
		if err := config.ConfigureOIDCProvider(portal, body); err == nil || portal.OIDCProvider != before {
			t.Fatal("second provider changed portal")
		}
	}
	config.AuthenticationPortals[0].OIDCProvider.Clients[0].Scopes[0] = "changed"
	if config.AuthenticationPortals[1].OIDCProvider.Clients[0].Scopes[0] != "openid" || config.OAuthApplications[0].Client.Scopes[0] != "openid" {
		t.Fatal("providers share mutable registrations")
	}
	for _, directives := range [][]string{
		{"disabled", "applications missing"}, {"disabled", "applications web web"}, {"unknown value"},
		{"issuer https://auth.example.test/api/identity", "realms local", "signing key files private.pem", "applications web"},
	} {
		portal := &authn.PortalConfig{Name: "invalid"}
		if err := config.ConfigureOIDCProvider(portal, directives); err == nil || portal.OIDCProvider != nil {
			t.Fatal("invalid provider changed portal")
		}
	}
	alias, err := oidc.NewOAuthApplicationConfig("duplicate-id", config.OAuthApplications[0].Client)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.AddOAuthApplication(alias); err != nil {
		t.Fatal(err)
	}
	if err := config.ConfigureOIDCProvider(&authn.PortalConfig{}, []string{"disabled", "applications web duplicate-id"}); err == nil {
		t.Fatal("duplicate selected client ID accepted")
	}
	if err := config.ConfigureOIDCProvider(nil, nil); err == nil {
		t.Fatal("nil portal accepted")
	}
	if err := config.ConfigureOIDCProvider(&authn.PortalConfig{Name: "disabled"}, []string{"disabled"}); err != nil {
		t.Fatal(err)
	}
}
