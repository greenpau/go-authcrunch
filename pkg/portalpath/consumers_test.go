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

package portalpath_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	"github.com/greenpau/go-authcrunch/pkg/httpserver"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
	ticketparser "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
	registration "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
	registrationparser "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite/parser"
)

func testOIDCMount(mount string) *oidc.Config {
	return &oidc.Config{Enabled: true, Issuer: "https://auth.example.test" + strings.TrimSuffix(mount, "/"), Realms: []string{"local"}, SigningKeyFiles: []string{"not-opened.pem"}, Clients: []*oidc.ClientConfig{{ClientID: "client", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.example.test/callback"}}}}
}

func TestPortalMountConsumers(t *testing.T) {
	database := filepath.Join(t.TempDir(), "not-opened.db")
	cases := append(mountCases(t), mountCase{"/équipe", true}, mountCase{"/neutral;parameter", true})
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			refresh := &authn.TokenRefreshConfig{Enabled: true, PublicOrigin: "https://auth.example.test", BasePath: tc.path, Realms: []string{"local"}}
			ticket := &tickets.Config{Name: "tickets", Realm: "login", Path: database, PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/login", BasePath: tc.path}
			registry := &registration.Config{Name: "enroll", IdentityStore: "accounts", Realm: "login", EmailProvider: "mail", Path: database, PublicOrigin: "https://auth.example.test", BasePath: tc.path}
			consumers := map[string]func() error{
				"standalone HTTP": func() error {
					return (&httpserver.Config{InsecureHTTP: true, Portals: []httpserver.PortalRoute{{Name: "portal", Path: tc.path}}}).Validate()
				},
				"refresh typed": refresh.Validate,
				"refresh parser": func() error {
					_, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"public origin https://auth.example.test", "realms local", cfgutil.EncodeArgs([]string{"base", "path", tc.path})})
					return err
				},
				"portal OP setter": func() error { return (&authn.PortalConfig{}).ConfigureOIDCProvider(testOIDCMount(tc.path)) },
				"portal OP typed": func() error {
					return (&authn.PortalConfig{Name: "portal", OIDCProvider: testOIDCMount(tc.path)}).Validate()
				},
				"ticket typed": ticket.Validate,
				"ticket parser": func() error {
					_, err := ticketparser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm login", cfgutil.EncodeArgs([]string{"path", database}), "public_origin https://auth.example.test", "issuer_url https://issuer.example.test/login", cfgutil.EncodeArgs([]string{"base_path", tc.path})})
					return err
				},
				"registration typed": registry.Validate,
				"registration parser": func() error {
					_, err := registrationparser.NewSQLiteRegistrationConfigFromDirectives([]string{"name enroll", "identity_store accounts", "realm login", "email_provider mail", cfgutil.EncodeArgs([]string{"path", database}), "public_origin https://auth.example.test", cfgutil.EncodeArgs([]string{"base_path", tc.path})})
					return err
				},
			}
			for name, validate := range consumers {
				t.Run(name, func(t *testing.T) {
					// SQLite's existing simple-segment language also rejects dotted
					// lookalikes such as TEAM-.well-known; generic mounts allow them.
					rejected := tc.reserved || ((strings.HasPrefix(name, "ticket") || strings.HasPrefix(name, "registration")) && strings.Contains(tc.path, "."))
					if err := validate(); (err != nil) != rejected {
						t.Fatalf("rejected=%t, validation error=%v", rejected, err)
					}
				})
			}
		})
	}
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("pure mount validation opened backend storage")
	}
}

func TestPortalMountConsumerBoundaries(t *testing.T) {
	if err := (&authn.TokenRefreshConfig{BasePath: "/login", PublicOrigin: "invalid"}).Validate(); err != nil {
		t.Fatal("disabled refresh changed ignored configuration behavior")
	}
	if err := (&authn.PortalConfig{}).ConfigureOIDCProvider(&oidc.Config{Issuer: "invalid"}); err != nil {
		t.Fatal("disabled OP changed ignored configuration behavior")
	}
	standalone := testOIDCMount("/login-service")
	if err := standalone.Validate(); err != nil {
		t.Fatal("portal policy leaked into standalone OP")
	}
	c := &authn.TokenRefreshConfig{Enabled: true, PublicOrigin: "https://auth.example.test", Realms: []string{"local"}, BasePath: "/neutral;parameter"}
	if c.Validate() == nil {
		t.Fatal("refresh accepted a path that changes browser cookie scope")
	}
	database := filepath.Join(t.TempDir(), "unused.db")
	for _, mount := range []string{"/équipe", "/" + strings.Repeat("a", 512)} {
		if (&tickets.Config{Name: "tickets", Realm: "login", Path: database, PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/login", BasePath: mount}).Validate() == nil {
			t.Fatal("ticket lost stricter segment/length rules")
		}
		if (&registration.Config{Name: "enroll", IdentityStore: "accounts", Realm: "login", EmailProvider: "mail", Path: database, PublicOrigin: "https://auth.example.test", BasePath: mount}).Validate() == nil {
			t.Fatal("registration lost stricter segment/length rules")
		}
	}
	ticket := &tickets.Config{Name: "tickets", Realm: "login", Path: database, PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/login"}
	if ticket.Validate() != nil || ticket.BasePath != "/auth" {
		t.Fatal("ticket default mount changed")
	}
	registry := &registration.Config{Name: "enroll", IdentityStore: "accounts", Realm: "login", EmailProvider: "mail", Path: database, PublicOrigin: "https://auth.example.test"}
	if registry.Validate() != nil || registry.BasePath != "/auth" {
		t.Fatal("registration default mount changed")
	}
}
