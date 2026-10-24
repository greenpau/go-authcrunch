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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

func externalRegistryTestConfig() *Config {
	cfg := externalIdentityTestConfig()
	cfg.ExternalUserRegistries = []*registry.ExternalUserRegistryConfig{{Name: "signup", Kind: "sqlite", IdentityStore: "accounts", Realm: "staff", EmailProvider: "mail", ConfigDigest: strings.Repeat("ab", 32)}}
	return cfg
}

func TestConfigExternalUserRegistries(t *testing.T) {
	cfg := externalRegistryTestConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthenticationPortals[0].UserRegistries) != 0 {
		t.Fatal("external enrollment implicitly enabled")
	}
	cfg.AuthenticationPortals[0].UserRegistries = []string{"signup", "signup"}
	for range 2 {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(cfg.AuthenticationPortals[0].UserRegistries, []string{"signup"}) {
			t.Fatal("registry selection is not stable")
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
	restored.ExternalUserRegistries[0].ConfigDigest = strings.Repeat("cd", 32)
	after, err := state.Binding(&restored)
	if err != nil || before == after {
		t.Fatal("registry digest did not affect persistent binding", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"nil descriptor", func(c *Config) { c.ExternalUserRegistries[0] = nil }},
		{"missing store", func(c *Config) { c.ExternalUserRegistries[0].IdentityStore = "missing" }},
		{"wrong realm", func(c *Config) { c.ExternalUserRegistries[0].Realm = "other" }},
		{"duplicate name", func(c *Config) {
			c.ExternalUserRegistries = append(c.ExternalUserRegistries, c.ExternalUserRegistries[0])
		}},
		{"duplicate store", func(c *Config) {
			d := *c.ExternalUserRegistries[0]
			d.Name = "other"
			c.ExternalUserRegistries = append(c.ExternalUserRegistries, &d)
		}},
		{"unknown portal registry", func(c *Config) { c.AuthenticationPortals[0].UserRegistries = []string{"missing"} }},
		{"disabled selected store", func(c *Config) {
			c.AuthenticationPortals[0].UserRegistries = []string{"signup"}
			c.AddDisabledIdentityStore("accounts")
		}},
		{"unselected store", func(c *Config) {
			c.AuthenticationPortals[0].UserRegistries = []string{"signup"}
			c.AuthenticationPortals[0].IdentityStores = []string{"other"}
		}},
		{"nil local", func(c *Config) {
			c.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{nil}}
		}},
		{"local name collision", func(c *Config) {
			c.IdentityStores = []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local"}}}
			c.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "signup", IdentityStoreName: "local"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := externalRegistryTestConfig()
			tc.change(c)
			if c.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	local := &Config{IdentityStores: []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local", Params: map[string]any{"realm": "staff"}}}, UserRegistration: &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "signup", IdentityStoreName: "accounts"}}}, AuthenticationPortals: []*authn.PortalConfig{{Name: "portal"}}}
	for range 2 {
		if err := local.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(local.AuthenticationPortals[0].UserRegistries, []string{"signup"}) || local.UserRegistration.LocalProviders[0].RealmName != "staff" {
		t.Fatal("legacy default did not select actual registry name and bind realm")
	}
	local.AuthenticationPortals[0].UserRegistries = nil
	local.AddDisabledIdentityStore("accounts")
	if err := local.Validate(); err != nil || len(local.AuthenticationPortals[0].UserRegistries) != 0 {
		t.Fatal("disabled local store gained registry", err)
	}
	mixed := externalRegistryTestConfig()
	mixed.IdentityStores = []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local"}}}
	mixed.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "local-signup", IdentityStoreName: "local"}}}
	for _, selection := range [][]string{{"signup"}, {"local-signup"}, {"signup", "local-signup"}} {
		mixed.AuthenticationPortals[0].IdentityStores = nil
		mixed.AuthenticationPortals[0].UserRegistries = slices.Clone(selection)
		if err := mixed.Validate(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(mixed.AuthenticationPortals[0].UserRegistries, selection) {
			t.Fatal("explicit mixed selection changed")
		}
	}

}

type externalRegistryFixture struct {
	registry.Provider
	name, kind, store, realm, email string
	invalid, panics                 bool
}

func (r *externalRegistryFixture) GetName() string              { return r.name }
func (r *externalRegistryFixture) Kind() string                 { return r.kind }
func (r *externalRegistryFixture) GetIdentityStoreName() string { return r.store }
func (r *externalRegistryFixture) GetRealmName() string         { return r.realm }
func (r *externalRegistryFixture) GetEmailProvider() string     { return r.email }
func (r *externalRegistryFixture) Validate() error {
	if r.panics {
		panic("synthetic validation panic")
	}
	if r.invalid {
		return errors.New("synthetic private dependency")
	}
	return nil
}
func TestServerExternalUserRegistryBindingValidation(t *testing.T) {
	fresh := func() *externalRegistryFixture {
		return &externalRegistryFixture{name: "signup", kind: "sqlite", store: "accounts", realm: "staff", email: "mail"}
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]registry.Provider, *Config)
	}{
		{"missing", func(b map[string]registry.Provider, _ *Config) { delete(b, "signup") }},
		{"nil", func(b map[string]registry.Provider, _ *Config) { b["signup"] = nil }},
		{"typed nil", func(b map[string]registry.Provider, _ *Config) { b["signup"] = (*externalRegistryFixture)(nil) }},
		{"wrong name", func(b map[string]registry.Provider, _ *Config) { b["signup"].(*externalRegistryFixture).name = "other" }},
		{"wrong kind", func(b map[string]registry.Provider, _ *Config) { b["signup"].(*externalRegistryFixture).kind = "local" }},
		{"wrong store", func(b map[string]registry.Provider, _ *Config) {
			b["signup"].(*externalRegistryFixture).store = "other"
		}},
		{"wrong realm", func(b map[string]registry.Provider, _ *Config) {
			b["signup"].(*externalRegistryFixture).realm = "other"
		}},
		{"wrong email", func(b map[string]registry.Provider, _ *Config) {
			b["signup"].(*externalRegistryFixture).email = "other"
		}},
		{"panicking validation", func(b map[string]registry.Provider, _ *Config) { b["signup"].(*externalRegistryFixture).panics = true }},
		{"unready", func(b map[string]registry.Provider, _ *Config) { b["signup"].(*externalRegistryFixture).invalid = true }},
		{"undeclared", func(b map[string]registry.Provider, _ *Config) { b["other"] = fresh() }},
		{"missing messaging", func(_ map[string]registry.Provider, c *Config) { c.Messaging = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := externalRegistryTestConfig()
			c.State = &state.Config{Directory: filepath.Join(t.TempDir(), "unacquired")}
			c.Messaging = &messaging.Config{FileProviders: []*messaging.FileProvider{{Name: "mail"}}}
			bindings := map[string]registry.Provider{"signup": fresh()}
			tc.change(bindings, c)
			opts := ServerOptions{IdentityStores: map[string]ids.IdentityStore{"accounts": &externalIdentityFixture{name: "accounts", realm: "staff", kind: "sqlite", configured: true}}, UserRegistries: bindings}
			if root, err := NewServerWithOptions(c, zap.NewNop(), opts); root != nil || err == nil {
				t.Fatal("invalid borrowed registry accepted")
			} else if strings.Contains(err.Error(), "synthetic private dependency") {
				t.Fatal("backend detail leaked")
			}
			if _, err := os.Stat(c.State.Directory); !os.IsNotExist(err) {
				t.Fatal("invalid binding acquired state")
			}
		})
	}
	c := externalRegistryTestConfig()
	c.Messaging = &messaging.Config{FileProviders: []*messaging.FileProvider{{Name: "mail"}}}
	if err := validateExternalUserRegistryBindings(c, map[string]registry.Provider{"signup": fresh()}); err != nil {
		t.Fatal(err)
	}
}
