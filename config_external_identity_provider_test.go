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

package authcrunch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/state"
	ticketparser "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
	"go.uber.org/zap"
)

func externalProviderTestConfig() *Config {
	return &Config{ExternalIdentityProviders: []*idp.ExternalIdentityProviderConfig{{Name: "tickets", Kind: "sqlite-ticket", Driver: "ticket", Realm: "application", ConfigDigest: strings.Repeat("ab", 32)}}, AuthenticationPortals: []*authn.PortalConfig{{Name: "portal"}}}
}

func TestConfigExternalIdentityProviders(t *testing.T) {
	cfg := externalProviderTestConfig()
	for range 2 {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(cfg.AuthenticationPortals[0].IdentityProviders, []string{"tickets"}) {
			t.Fatal("external provider default selection changed")
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored Config
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	before, err := state.Binding(&restored)
	if err != nil {
		t.Fatal(err)
	}
	restored.ExternalIdentityProviders[0].ConfigDigest = strings.Repeat("cd", 32)
	after, err := state.Binding(&restored)
	if err != nil || before == after {
		t.Fatal("external provider config did not affect persistent binding", err)
	}
	builtin := func(name, realm string) *idp.IdentityProviderConfig {
		return &idp.IdentityProviderConfig{Name: name, Kind: "oauth", Params: map[string]any{"realm": realm}}
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"nil descriptor", func(c *Config) { c.ExternalIdentityProviders[0] = nil }},
		{"invalid descriptor", func(c *Config) { c.ExternalIdentityProviders[0].ConfigDigest = "" }},
		{"duplicate external name", func(c *Config) {
			c.ExternalIdentityProviders = append(c.ExternalIdentityProviders, c.ExternalIdentityProviders[0])
		}},
		{"builtin name collision", func(c *Config) { c.IdentityProviders = []*idp.IdentityProviderConfig{builtin("tickets", "other")} }},
		{"duplicate builtin name", func(c *Config) {
			c.IdentityProviders = []*idp.IdentityProviderConfig{builtin("other", "one"), builtin("other", "two")}
		}},
		{"nil builtin", func(c *Config) { c.IdentityProviders = []*idp.IdentityProviderConfig{nil} }},
		{"invalid builtin realm type", func(c *Config) {
			c.IdentityProviders = []*idp.IdentityProviderConfig{{Name: "other", Kind: "oauth", Params: map[string]any{"realm": 1}}}
		}},
		{"unknown provider without builtin", func(c *Config) { c.AuthenticationPortals[0].IdentityProviders = []string{"missing"} }},
		{"unknown cannot borrow final builtin realm", func(c *Config) {
			c.IdentityProviders = []*idp.IdentityProviderConfig{builtin("other", "legacy")}
			c.AuthenticationPortals[0].IdentityProviders = []string{"missing"}
		}},
		{"duplicate selected provider", func(c *Config) { c.AuthenticationPortals[0].IdentityProviders = []string{"tickets", "tickets"} }},
		{"builtin realm collision", func(c *Config) { c.IdentityProviders = []*idp.IdentityProviderConfig{builtin("legacy", "application")} }},
		{"external realm collision", func(c *Config) {
			d := *c.ExternalIdentityProviders[0]
			d.Name = "other"
			c.ExternalIdentityProviders = append(c.ExternalIdentityProviders, &d)
		}},
		{"local store realm collision", func(c *Config) {
			c.IdentityStores = []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "application"}}}
		}},
		{"external store realm collision", func(c *Config) {
			c.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "accounts", Kind: "sqlite", Realm: "application", ConfigDigest: strings.Repeat("ab", 32)}}
		}},
		{"store name collision", func(c *Config) {
			c.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "tickets", Kind: "sqlite", Realm: "staff", ConfigDigest: strings.Repeat("ab", 32)}}
		}},
		{"nil portal", func(c *Config) { c.AuthenticationPortals[0] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := externalProviderTestConfig()
			tc.change(c)
			if c.Validate() == nil {
				t.Fatal("invalid provider selection accepted")
			}
		})
	}
	// A backend with the same realm may exist when it is not selected. Explicit
	// selection must not expand and enable a second source of authority.
	cfg = externalProviderTestConfig()
	cfg.IdentityProviders = []*idp.IdentityProviderConfig{builtin("legacy", "application")}
	cfg.AuthenticationPortals[0].IdentityProviders = []string{"tickets"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.AuthenticationPortals[0].IdentityProviders, []string{"tickets"}) {
		t.Fatal("explicit selection expanded")
	}
	cfg = externalProviderTestConfig()
	cfg.IdentityProviders = []*idp.IdentityProviderConfig{builtin("legacy", "application")}
	cfg.AddDisabledIdentityProvider("legacy")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.AuthenticationPortals[0].IdentityProviders, []string{"tickets"}) {
		t.Fatal("disabled builtin was selected")
	}
	cfg.AddDisabledIdentityProvider("tickets")
	if err := cfg.Validate(); err != nil || len(cfg.AuthenticationPortals[0].IdentityProviders) != 0 {
		t.Fatal("disabled external was selected", err)
	}
}

func TestExternalIdentityProviderNormalizedBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unopened.db")
	directives := []string{"name tickets", "realm application", "path " + path, "public_origin https://portal.example.test", "issuer_url https://issuer.example.test/login"}
	base, err := ticketparser.NewSQLiteTicketProviderConfigFromDirectives(directives)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := ticketparser.NewSQLiteTicketProviderConfigFromDirectives(append(slices.Clone(directives), "timeout 1000ms"))
	if err != nil {
		t.Fatal(err)
	}
	// The generic descriptor does not interpret backend duration fields. The
	// host canonicalizes equivalent spellings before passing normalized input.
	duration, err := time.ParseDuration(explicit.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	explicit.Timeout = duration.String()
	first, err := idp.NewExternalIdentityProviderConfig(base.Name, "sqlite-ticket", "ticket", base.Realm, base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := idp.NewExternalIdentityProviderConfig(explicit.Name, "sqlite-ticket", "ticket", explicit.Realm, explicit)
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfigDigest != second.ConfigDigest {
		t.Fatal("equivalent normalized timeouts changed descriptor")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pure descriptor preparation acquired storage")
	}
}

type externalProviderFixture struct {
	idp.IdentityProvider
	name, kind, driver, realm               string
	configured, panicReady, panicAttachment bool
	configures, closes                      int
	attached                                *attachment.Attachment
}

func (p *externalProviderFixture) GetName() string   { return p.name }
func (p *externalProviderFixture) GetKind() string   { return p.kind }
func (p *externalProviderFixture) GetDriver() string { return p.driver }
func (p *externalProviderFixture) GetRealm() string  { return p.realm }
func (p *externalProviderFixture) Configured() bool {
	if p.panicReady {
		panic("synthetic private readiness")
	}
	return p.configured
}
func (p *externalProviderFixture) Configure() error { p.configures++; return nil }
func (p *externalProviderFixture) Close() error     { p.closes++; return nil }
func (p *externalProviderFixture) GetLoginIcon() *icons.LoginIcon {
	return &icons.LoginIcon{Text: "Ticket"}
}
func (p *externalProviderFixture) GetIdentityTokenCookieName() string { return "" }
func (p *externalProviderFixture) GetLogoutURL() string               { return "" }
func (p *externalProviderFixture) GetConfig() map[string]any          { return map[string]any{"name": p.name} }
func (p *externalProviderFixture) IdentityAttachment() *attachment.Attachment {
	if p.panicAttachment {
		panic("synthetic private attachment")
	}
	return p.attached
}
func newExternalProviderFixture(t *testing.T) *externalProviderFixture {
	t.Helper()
	a, err := attachment.New(attachment.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &externalProviderFixture{name: "tickets", kind: "sqlite-ticket", driver: "ticket", realm: "application", configured: true, attached: a}
}

func TestServerExternalIdentityProviderBindingValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]idp.IdentityProvider)
	}{
		{"missing", func(b map[string]idp.IdentityProvider) { delete(b, "tickets") }},
		{"nil", func(b map[string]idp.IdentityProvider) { b["tickets"] = nil }},
		{"typed nil", func(b map[string]idp.IdentityProvider) { b["tickets"] = (*externalProviderFixture)(nil) }},
		{"wrong name", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).name = "other" }},
		{"wrong kind", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).kind = "oauth" }},
		{"wrong driver", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).driver = "other" }},
		{"wrong realm", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).realm = "other" }},
		{"unavailable", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).configured = false }},
		{"readiness panic", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).panicReady = true }},
		{"nil attachment", func(b map[string]idp.IdentityProvider) { b["tickets"].(*externalProviderFixture).attached = nil }},
		{"unbound explicit attachment", func(b map[string]idp.IdentityProvider) {
			a, err := attachment.New(attachment.Config{LocalIdentityStore: "unbound"})
			if err != nil {
				t.Fatal(err)
			}
			b["tickets"].(*externalProviderFixture).attached = a
		}},
		{"attachment accessor panic", func(b map[string]idp.IdentityProvider) {
			b["tickets"].(*externalProviderFixture).panicAttachment = true
		}},
		{"extra", func(b map[string]idp.IdentityProvider) { b["other"] = newExternalProviderFixture(t) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := externalProviderTestConfig()
			cfg.State = &state.Config{Directory: filepath.Join(t.TempDir(), "unacquired")}
			provider := newExternalProviderFixture(t)
			bindings := map[string]idp.IdentityProvider{"tickets": provider}
			tc.change(bindings)
			if root, err := NewServerWithOptions(cfg, zap.NewNop(), ServerOptions{IdentityProviders: bindings}); err == nil || root != nil {
				t.Fatal("invalid runtime accepted")
			} else if strings.Contains(err.Error(), "synthetic private") {
				t.Fatal("readiness detail leaked")
			}
			if _, err := os.Stat(cfg.State.Directory); !os.IsNotExist(err) {
				t.Fatal("invalid provider acquired root state")
			}
			if provider.configures != 0 || provider.closes != 0 {
				t.Fatal("root mutated borrowed provider")
			}
		})
	}
}

func TestServerExternalIdentityProviderOwnership(t *testing.T) {
	provider := newExternalProviderFixture(t)
	attached, err := attachment.New(attachment.Config{LocalIdentityStore: "caller-owned"})
	if err != nil {
		t.Fatal(err)
	}
	database, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := attachment.BindStore(attached, database); err != nil {
		t.Fatal(err)
	}
	provider.attached = attached
	options := ServerOptions{IdentityProviders: map[string]idp.IdentityProvider{"tickets": provider}}
	config := func() *Config {
		c := externalProviderTestConfig()
		c.AuthenticationPortals = append(c.AuthenticationPortals, &authn.PortalConfig{Name: "second"})
		return c
	}
	// No root store of this name exists. Root construction must retain the
	// ready external binding, without attempting to resolve or rebind it.
	root, err := NewServerWithOptions(config(), zap.NewNop(), options)
	if err != nil {
		t.Fatal(err)
	}
	if root.nameRefs.identityProviders["tickets"] != provider || root.identityProviders[0] != provider {
		t.Fatal("dynamic provider instance replaced")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	candidate := config()
	candidate.AuthenticationPortals[1].Name = "portal"
	if root, err := NewServerWithOptions(candidate, zap.NewNop(), options); root != nil || err == nil {
		t.Fatal("invalid candidate accepted")
	}
	if provider.configures != 0 || provider.closes != 0 {
		t.Fatal("root configured or closed borrowed provider")
	}
	preserved, err := provider.attached.Store()
	if err != nil || preserved != database {
		t.Fatal("root replaced caller-owned attachment", err)
	}
	// Standalone portals retain automatic attachment resolution unless their
	// caller explicitly says all wiring is already complete.
	_, err = authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "standalone", IdentityProviders: []string{"tickets"}}, IdentityProviders: []idp.IdentityProvider{provider}, Logger: zap.NewNop()})
	if err == nil || !strings.Contains(err.Error(), "attached local identity store not found") {
		t.Fatal("standalone attachment default changed", err)
	}
}

type externalAttachmentStoreFixture struct {
	externalIdentityFixture
	attached        *attachment.Attachment
	panicAttachment bool
}

func (s *externalAttachmentStoreFixture) IdentityAttachment() *attachment.Attachment {
	if s.panicAttachment {
		panic("synthetic private attachment")
	}
	return s.attached
}
func (s *externalAttachmentStoreFixture) GetLoginIcon() *icons.LoginIcon {
	return icons.NewLoginIcon("local")
}
func (s *externalAttachmentStoreFixture) GetConfig() map[string]any {
	return map[string]any{"name": s.name}
}

func TestServerExternalIdentityProviderPreservesBorrowedStoreAttachment(t *testing.T) {
	attached, err := attachment.New(attachment.Config{LocalIdentityStore: "host-private"})
	if err != nil {
		t.Fatal(err)
	}
	database, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := attachment.BindStore(attached, database); err != nil {
		t.Fatal(err)
	}
	store := &externalAttachmentStoreFixture{externalIdentityFixture: externalIdentityFixture{name: "accounts", kind: "sqlite", realm: "staff", configured: true}, attached: attached}
	cfg := externalProviderTestConfig()
	cfg.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "accounts", Kind: "sqlite", Realm: "staff", ConfigDigest: strings.Repeat("ab", 32)}}
	root, err := NewServerWithOptions(cfg, zap.NewNop(), ServerOptions{IdentityProviders: map[string]idp.IdentityProvider{"tickets": newExternalProviderFixture(t)}, IdentityStores: map[string]ids.IdentityStore{"accounts": store}})
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	preserved, err := attached.Store()
	if err != nil || preserved != database || store.closes != 0 {
		t.Fatal("root changed borrowed store attachment", err)
	}
}

func TestServerExternalIdentityProviderOwnedLDAPAttachment(t *testing.T) {
	file := filepath.Join(t.TempDir(), "accounts.json")
	if _, err := identity.NewDatabase(file); err != nil {
		t.Fatal(err)
	}
	cfg := externalProviderTestConfig()
	cfg.IdentityStores = []*ids.IdentityStoreConfig{
		{Name: "local", Kind: "local", Params: map[string]any{"path": file, "realm": "local"}},
		{Name: "ldap", Kind: "ldap", Params: map[string]any{"realm": "directory", "servers": []map[string]any{{"address": "ldaps://127.0.0.1:636", "timeout": 1}}, "bind_username": "cn=service,dc=example,dc=test", "bind_password": "synthetic-service-password", "search_base_dn": "dc=example,dc=test", "groups": []map[string]any{{"dn": "cn=members,dc=example,dc=test", "roles": []string{"authp/user"}}}, "attachment": &attachment.Config{LocalIdentityStore: "local"}}},
	}
	root, err := NewServerWithOptions(cfg, zap.NewNop(), ServerOptions{IdentityProviders: map[string]idp.IdentityProvider{"tickets": newExternalProviderFixture(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owned := root.nameRefs.identityStores["ldap"].(attachment.Consumer).IdentityAttachment()
	actual, err := owned.Store()
	if err != nil || any(actual) != any(root.nameRefs.identityStores["local"]) {
		t.Fatal("owned LDAP attachment was not bound before portal assembly", err)
	}
}

func TestServerExternalIdentityProviderRejectsBorrowedStoreAttachment(t *testing.T) {
	for _, failure := range []string{"nil", "unbound", "panic"} {
		t.Run(failure, func(t *testing.T) {
			store := &externalAttachmentStoreFixture{externalIdentityFixture: externalIdentityFixture{name: "accounts", kind: "sqlite", realm: "staff", configured: true}}
			if failure == "unbound" {
				var err error
				store.attached, err = attachment.New(attachment.Config{LocalIdentityStore: "unbound"})
				if err != nil {
					t.Fatal(err)
				}
			}
			store.panicAttachment = failure == "panic"
			cfg := externalProviderTestConfig()
			cfg.State = &state.Config{Directory: filepath.Join(t.TempDir(), "unacquired")}
			cfg.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "accounts", Kind: "sqlite", Realm: "staff", ConfigDigest: strings.Repeat("ab", 32)}}
			options := ServerOptions{IdentityProviders: map[string]idp.IdentityProvider{"tickets": newExternalProviderFixture(t)}, IdentityStores: map[string]ids.IdentityStore{"accounts": store}}
			if root, err := NewServerWithOptions(cfg, zap.NewNop(), options); root != nil || err == nil {
				t.Fatal("unready attachment accepted")
			} else if strings.Contains(err.Error(), "synthetic private") {
				t.Fatal("private attachment detail leaked")
			}
			if _, err := os.Stat(cfg.State.Directory); !os.IsNotExist(err) {
				t.Fatal("unready attachment acquired root state")
			}
			if store.closes != 0 {
				t.Fatal("root closed caller-owned store")
			}
		})
	}
}
