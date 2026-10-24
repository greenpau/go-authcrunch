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
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"go.uber.org/zap"
)

type registryIconStore struct {
	ids.IdentityStore
	icon *icons.LoginIcon
}

func (*registryIconStore) GetName() string                  { return "accounts" }
func (*registryIconStore) GetRealm() string                 { return "staff" }
func (*registryIconStore) GetKind() string                  { return "sqlite" }
func (s *registryIconStore) GetLoginIcon() *icons.LoginIcon { return s.icon }

type registryPortalFixture struct {
	registry.Provider
	name, store, realm string
	changes            int
}

func (r *registryPortalFixture) GetName() string              { return r.name }
func (r *registryPortalFixture) GetIdentityStoreName() string { return r.store }
func (r *registryPortalFixture) GetRealmName() string         { return r.realm }
func (r *registryPortalFixture) SetRealmName(string)          { r.changes++ }
func (r *registryPortalFixture) AsMap() map[string]any        { return map[string]any{"name": r.name} }
func TestPortalUserRegistrySelectionAndDetachedIcons(t *testing.T) {
	icon := icons.NewLoginIcon("local")
	icon.SetRealm("unchanged")
	shared := &registryIconStore{icon: icon}
	makePortal := func(names []string) *Portal {
		return &Portal{config: &PortalConfig{Name: "portal", UserRegistries: names}, identityStores: []ids.IdentityStore{shared}, loginOptions: map[string]any{}, logger: zap.NewNop()}
	}
	enabled, disabled := makePortal([]string{"signup"}), makePortal(nil)
	for _, p := range []*Portal{enabled, disabled} {
		if err := p.configureLoginIcons(); err != nil {
			t.Fatal(err)
		}
	}
	signup := &registryPortalFixture{name: "signup", store: "accounts", realm: "staff"}
	if err := enabled.AddUserRegistry(signup); err != nil {
		t.Fatal(err)
	}
	visible := func(p *Portal) bool {
		return p.loginOptions["authenticators"].([]map[string]string)[0]["registration_enabled"] == "yes"
	}
	if !visible(enabled) || visible(disabled) || icon.RegistrationEnabled || icon.Realm != "unchanged" {
		t.Fatal("signup metadata escaped selected portal")
	}
	for range 3 {
		if enabled.GetUserRegistryByRealmName("staff") != signup || enabled.GetUserRegistryByRealmName("other") != nil {
			t.Fatal("wrong registry lookup")
		}
	}
	if signup.changes != 0 {
		t.Fatal("lookup mutated borrowed provider")
	}
	if err := disabled.AddUserRegistry(signup); err == nil {
		t.Fatal("unselected registration attached")
	}
	if err := enabled.AddUserRegistry(signup); err == nil {
		t.Fatal("duplicate registration attached")
	}
	for _, invalid := range []registry.Provider{nil, &registryPortalFixture{name: "unknown", store: "accounts", realm: "staff"}, &registryPortalFixture{name: "signup", store: "missing", realm: "staff"}, &registryPortalFixture{name: "signup", store: "accounts", realm: "other"}} {
		p := makePortal([]string{"signup"})
		if err := p.AddUserRegistry(invalid); err == nil {
			t.Fatal("invalid registry attached")
		}
	}
	p := makePortal([]string{"signup"})
	local := &registry.LocalUserRegistryProvider{Name: "signup", IdentityStoreName: "accounts"}
	if err := p.AddUserRegistry(local); err != nil || local.RealmName != "staff" {
		t.Fatal("omitted local realm was not bound before serving", err)
	}
	broken := makePortal([]string{"signup"})
	broken.identityStores = []ids.IdentityStore{&registryIconStore{}}
	if err := broken.AddUserRegistry(signup); err == nil || len(broken.userRegistries) != 0 {
		t.Fatal("failed icon build published registry")
	}
}
