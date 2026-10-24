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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"go.uber.org/zap"
)

type externalIdentityFixture struct {
	ids.IdentityStore
	name, realm, kind string
	configured        bool
	closes            int
}

func (s *externalIdentityFixture) GetName() string  { return s.name }
func (s *externalIdentityFixture) GetRealm() string { return s.realm }
func (s *externalIdentityFixture) GetKind() string  { return s.kind }
func (s *externalIdentityFixture) Configured() bool { return s.configured }
func (s *externalIdentityFixture) Close() error     { s.closes++; return nil }

func externalIdentityTestConfig() *Config {
	return &Config{ExternalIdentityStores: []*ids.ExternalIdentityStoreConfig{{Name: "accounts", Kind: "sqlite", Realm: "staff", ConfigDigest: strings.Repeat("ab", 32)}}, AuthenticationPortals: []*authn.PortalConfig{{Name: "portal"}}}
}
func TestConfigExternalIdentityStores(t *testing.T) {
	cfg := externalIdentityTestConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthenticationPortals[0].IdentityStores) != 1 || cfg.AuthenticationPortals[0].IdentityStores[0] != "accounts" {
		t.Fatal("default selection missed external store")
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
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"duplicate descriptor", func(c *Config) {
			c.ExternalIdentityStores = append(c.ExternalIdentityStores, c.ExternalIdentityStores[0])
		}},
		{"built-in collision", func(c *Config) { c.IdentityStores = []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local"}} }},
		{"nil descriptor", func(c *Config) { c.ExternalIdentityStores[0] = nil }},
		{"duplicate portal name", func(c *Config) { c.AuthenticationPortals[0].IdentityStores = []string{"accounts", "accounts"} }},
		{"duplicate external realm", func(c *Config) {
			c.ExternalIdentityStores = append(c.ExternalIdentityStores, &ids.ExternalIdentityStoreConfig{Name: "other", Kind: "sqlite", Realm: "staff", ConfigDigest: strings.Repeat("ab", 32)})
		}},
		{"overlapping built-in realm", func(c *Config) {
			c.IdentityStores = []*ids.IdentityStoreConfig{{Name: "builtin", Kind: "local", Params: map[string]any{"realm": "staff", "path": "/unused"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := externalIdentityTestConfig()
			tc.mutate(cfg)
			if cfg.Validate() == nil {
				t.Fatal("ambiguous configuration accepted")
			}
		})
	}
	cfg = externalIdentityTestConfig()
	cfg.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "registration", IdentityStoreName: "accounts"}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "local user registry") {
		t.Fatal("local registry accepted an external identity store", err)
	}
	cfg = externalIdentityTestConfig()
	cfg.AddDisabledIdentityStore("accounts")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthenticationPortals[0].IdentityStores) != 0 {
		t.Fatal("disabled external store selected")
	}
}
func TestServerExternalIdentityStoreBindingValidation(t *testing.T) {
	fresh := func() *externalIdentityFixture {
		return &externalIdentityFixture{name: "accounts", kind: "sqlite", realm: "staff", configured: true}
	}
	for _, tc := range []struct {
		name     string
		bindings func() map[string]ids.IdentityStore
	}{
		{"missing", func() map[string]ids.IdentityStore { return nil }},
		{"nil", func() map[string]ids.IdentityStore { return map[string]ids.IdentityStore{"accounts": nil} }},
		{"typed nil", func() map[string]ids.IdentityStore {
			return map[string]ids.IdentityStore{"accounts": (*externalIdentityFixture)(nil)}
		}},
		{"wrong name", func() map[string]ids.IdentityStore {
			s := fresh()
			s.name = "other"
			return map[string]ids.IdentityStore{"accounts": s}
		}},
		{"wrong realm", func() map[string]ids.IdentityStore {
			s := fresh()
			s.realm = "other"
			return map[string]ids.IdentityStore{"accounts": s}
		}},
		{"wrong kind", func() map[string]ids.IdentityStore {
			s := fresh()
			s.kind = "local"
			return map[string]ids.IdentityStore{"accounts": s}
		}},
		{"unconfigured", func() map[string]ids.IdentityStore {
			s := fresh()
			s.configured = false
			return map[string]ids.IdentityStore{"accounts": s}
		}},
		{"extra", func() map[string]ids.IdentityStore {
			return map[string]ids.IdentityStore{"accounts": fresh(), "extra": fresh()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bindings := tc.bindings()
			if root, err := NewServerWithOptions(externalIdentityTestConfig(), zap.NewNop(), ServerOptions{IdentityStores: bindings}); err == nil || root != nil {
				t.Fatal("invalid runtime binding accepted")
			}
			for _, store := range bindings {
				if s, ok := store.(*externalIdentityFixture); ok && s != nil && s.closes != 0 {
					t.Fatal("constructor closed caller-owned store")
				}
			}
		})
	}
	if err := validateExternalIdentityStoreBindings(externalIdentityTestConfig(), map[string]ids.IdentityStore{"accounts": fresh()}); err != nil {
		t.Fatal(err)
	}
}
