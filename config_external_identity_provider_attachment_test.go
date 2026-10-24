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
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func externalAttachmentConfig(path string) *Config {
	cfg := externalProviderTestConfig()
	cfg.AuthenticationPortals[0].IdentityProviders = []string{"tickets"}
	cfg.IdentityStores = []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local", Params: map[string]any{"realm": "local", "path": path}}}
	return cfg
}

func explicitExternalProvider(t *testing.T) *externalProviderFixture {
	t.Helper()
	provider := newExternalProviderFixture(t)
	var err error
	provider.attached, err = attachment.New(attachment.Config{LocalIdentityStore: "accounts"})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func externalAttachmentOptions(provider idp.IdentityProvider) ServerOptions {
	return ServerOptions{
		IdentityProviders:                map[string]idp.IdentityProvider{"tickets": provider},
		IdentityProviderAttachmentStores: map[string]string{"tickets": "accounts"},
	}
}

// Embedding only the public interface intentionally drops optional Consumer.
type providerWithoutAttachment struct{ idp.IdentityProvider }

func TestServerExternalIdentityProviderAttachmentPreflight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config, *ServerOptions, *externalProviderFixture)
	}{
		{"unknown opt-in", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) {
			o.IdentityProviderAttachmentStores["missing"] = "accounts"
		}},
		{"builtin opt-in", func(c *Config, o *ServerOptions, _ *externalProviderFixture) {
			c.IdentityProviders = []*idp.IdentityProviderConfig{{Name: "builtin", Kind: "oauth", Params: map[string]any{"realm": "other"}}}
			o.IdentityProviderAttachmentStores["builtin"] = "accounts"
		}},
		{"missing handle", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) { delete(o.IdentityProviders, "tickets") }},
		{"nil handle", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) { o.IdentityProviders["tickets"] = nil }},
		{"typed nil", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) {
			o.IdentityProviders["tickets"] = (*externalProviderFixture)(nil)
		}},
		{"not configured", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) { p.configured = false }},
		{"readiness panic", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) { p.panicReady = true }},
		{"attachment panic", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) { p.panicAttachment = true }},
		{"later provider invalid", func(c *Config, o *ServerOptions, _ *externalProviderFixture) {
			second := explicitExternalProvider(t)
			second.name, second.realm, second.panicAttachment = "second", "second", true
			descriptor := *c.ExternalIdentityProviders[0]
			descriptor.Name, descriptor.Realm = second.name, second.realm
			c.ExternalIdentityProviders = append(c.ExternalIdentityProviders, &descriptor)
			o.IdentityProviders["second"] = second
			o.IdentityProviderAttachmentStores["second"] = "accounts"
		}},
		{"not a consumer", func(_ *Config, o *ServerOptions, p *externalProviderFixture) {
			o.IdentityProviders["tickets"] = providerWithoutAttachment{p}
		}},
		{"nil attachment", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) { p.attached = nil }},
		{"implicit attachment", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) {
			p.attached = newExternalProviderFixture(t).attached
		}},
		{"mismatched attachment", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) {
			var err error
			p.attached, err = attachment.New(attachment.Config{LocalIdentityStore: "other"})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"empty target", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) {
			o.IdentityProviderAttachmentStores["tickets"] = ""
		}},
		{"memory target name", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) {
			o.IdentityProviderAttachmentStores["tickets"] = ":memory:"
		}},
		{"whitespace target", func(_ *Config, o *ServerOptions, _ *externalProviderFixture) {
			o.IdentityProviderAttachmentStores["tickets"] = " accounts"
		}},
		{"missing target", func(c *Config, _ *ServerOptions, _ *externalProviderFixture) { c.IdentityStores = nil }},
		{"wrong kind", func(c *Config, _ *ServerOptions, _ *externalProviderFixture) { c.IdentityStores[0].Kind = "ldap" }},
		{"duplicate target", func(c *Config, _ *ServerOptions, _ *externalProviderFixture) {
			c.IdentityStores = append(c.IdentityStores, c.IdentityStores[0])
		}},
		{"disabled target", func(c *Config, _ *ServerOptions, _ *externalProviderFixture) { c.AddDisabledIdentityStore("accounts") }},
		{"external target", func(c *Config, o *ServerOptions, _ *externalProviderFixture) {
			c.IdentityStores = nil
			c.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "accounts", Kind: "sqlite", Realm: "local", ConfigDigest: strings.Repeat("ab", 32)}}
			o.IdentityStores = map[string]ids.IdentityStore{"accounts": &externalIdentityFixture{name: "accounts", kind: "sqlite", realm: "local", configured: true}}
		}},
		{"already bound", func(_ *Config, _ *ServerOptions, p *externalProviderFixture) {
			db, err := identity.NewDatabase(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			if err := attachment.BindStore(p.attached, db); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "unopened.json")
			cfg := externalAttachmentConfig(path)
			cfg.State = &state.Config{Directory: filepath.Join(dir, "unacquired")}
			provider := explicitExternalProvider(t)
			options := externalAttachmentOptions(provider)
			tc.change(cfg, &options, provider)
			if root, err := NewServerWithOptions(cfg, zap.NewNop(), options); root != nil || err == nil {
				t.Fatal("invalid attachment opt-in accepted")
			} else if strings.Contains(err.Error(), "synthetic private") {
				t.Fatal("private plugin diagnostic escaped")
			}
			for _, unopened := range []string{path, cfg.State.Directory} {
				if _, err := os.Stat(unopened); !os.IsNotExist(err) {
					t.Fatal("invalid opt-in acquired root resources")
				}
			}
			if provider.configures != 0 || provider.closes != 0 {
				t.Fatal("preflight changed caller ownership")
			}
			if tc.name == "later provider invalid" {
				if _, err := provider.attached.Store(); err == nil {
					t.Fatal("preflight mutated an earlier valid provider")
				}
			}
		})
	}
}

type singleAttachmentAccessor struct {
	*externalProviderFixture
	reads int
}

func (p *singleAttachmentAccessor) IdentityAttachment() *attachment.Attachment {
	p.reads++
	if p.reads > 1 {
		panic("synthetic private repeated accessor")
	}
	return p.attached
}

func TestServerExternalIdentityProviderAttachmentOwnership(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory local target"
		if persistent {
			name = "persistent local target"
		}
		t.Run(name, func(t *testing.T) {
			path := ":memory:"
			if persistent {
				path = filepath.Join(t.TempDir(), "accounts.json")
			}
			cfg := externalAttachmentConfig(path)
			if persistent {
				cfg.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
			}
			provider := &singleAttachmentAccessor{externalProviderFixture: explicitExternalProvider(t)}
			second := explicitExternalProvider(t)
			second.name, second.realm = "second", "second"
			descriptor := *cfg.ExternalIdentityProviders[0]
			descriptor.Name, descriptor.Realm = second.name, second.realm
			cfg.ExternalIdentityProviders = append(cfg.ExternalIdentityProviders, &descriptor)
			cfg.AuthenticationPortals = append(cfg.AuthenticationPortals, &authn.PortalConfig{Name: "second", IdentityProviders: []string{"tickets", "second"}})
			options := externalAttachmentOptions(provider)
			options.IdentityProviders["second"] = second
			options.IdentityProviderAttachmentStores["second"] = "accounts"
			root, err := NewServerWithOptions(cfg, zap.NewNop(), options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := root.Close(); err != nil {
					t.Error(err)
				}
			})
			for _, p := range []*externalProviderFixture{provider.externalProviderFixture, second} {
				actual, err := p.attached.Store()
				if err != nil || any(actual) != any(root.nameRefs.identityStores["accounts"]) {
					t.Fatal("provider did not receive actual shared root local store")
				}
			}
			if provider.reads != 1 || root.nameRefs.identityProviders["tickets"] != provider {
				t.Fatal("root replaced provider or repeated plugin attachment accessor")
			}
			if len(cfg.AuthenticationPortals[0].IdentityStores) != 0 || len(cfg.AuthenticationPortals[1].IdentityStores) != 0 {
				t.Fatal("attachment silently enabled local login")
			}
			encoded, err := json.Marshal(options)
			if err != nil || string(encoded) != "{}" {
				t.Fatal("runtime attachment bindings became declarative configuration")
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			if provider.configures != 0 || provider.closes != 0 || second.configures != 0 || second.closes != 0 {
				t.Fatal("root assumed borrowed provider lifetime")
			}
		})
	}
}

func TestServerExternalIdentityProviderAttachmentFailureOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	provider := explicitExternalProvider(t)
	cfg := externalAttachmentConfig(path)
	cfg.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
	policy := &authz.PolicyConfig{
		Name:                    "bad",
		AuthProxyRawConfig:      []string{"api key auth realm other portal missing"},
		RawCryptoKeyStoreConfig: []string{"crypto key fixture verify from file testdata/rskeys/test_2_pub.pem"},
		AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
	}
	// Persistent roots validate policies before opening identity stores. Only
	// the later registration of the missing portal must reject this candidate.
	if err := policy.Validate(); err != nil {
		t.Fatal("fixture policy failed before runtime composition", err)
	}
	cfg.AuthorizationPolicies = []*authz.PolicyConfig{policy}
	if root, err := NewServerWithOptions(cfg, zap.NewNop(), externalAttachmentOptions(provider)); root != nil || err == nil || !strings.Contains(err.Error(), `token validator: auth proxy for "other" realm not found`) {
		t.Fatal("candidate did not reach the intended auth proxy failure", err)
	}
	bound, err := provider.attached.Store()
	if err != nil || bound == nil {
		t.Fatal("fixture did not fail after installing attachment")
	}
	if provider.configures != 0 || provider.closes != 0 {
		t.Fatal("failed root closed or configured borrowed provider")
	}
	storage, err := state.Open(cfg.State)
	if err != nil {
		t.Fatal("failed root retained state ownership", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	// Reusing an opted provider must fail before the new candidate opens either
	// its state or its otherwise valid account file; the old bind stays intact.
	freshPath := filepath.Join(t.TempDir(), "untouched.json")
	retry := externalAttachmentConfig(freshPath)
	retry.State = &state.Config{Directory: filepath.Join(t.TempDir(), "unacquired")}
	if root, err := NewServerWithOptions(retry, zap.NewNop(), externalAttachmentOptions(provider)); root != nil || err == nil || !strings.Contains(err.Error(), "already bound") {
		t.Fatal("bound provider reuse was not rejected in preflight")
	}
	for _, path := range []string{freshPath, retry.State.Directory} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("provider reuse touched candidate storage")
		}
	}
	retained, err := provider.attached.Store()
	if err != nil || retained != bound {
		t.Fatal("failed retry replaced caller attachment")
	}
	root, err := NewServerWithOptions(externalAttachmentConfig(freshPath), zap.NewNop(), externalAttachmentOptions(explicitExternalProvider(t)))
	if err != nil {
		t.Fatal("fresh provider could not recover after candidate failure", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerExternalIdentityProviderAttachmentSnapshotFailure(t *testing.T) {
	for _, phase := range []string{"identity epoch before binding", "portal sessions after binding"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "accounts.json")
			configuration := func() *Config {
				c := externalAttachmentConfig(path)
				c.State = &state.Config{Directory: filepath.Join(dir, "state")}
				return c
			}
			root, err := NewServerWithOptions(configuration(), zap.NewNop(), externalAttachmentOptions(explicitExternalProvider(t)))
			if err != nil {
				t.Fatal(err)
			}
			binding, err := root.persistentStateBinding(root.config)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(root.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			storage, err := state.Open(configuration().State)
			if err != nil {
				t.Fatal(err)
			}
			name := "portal-sessions/portal"
			if phase == "identity epoch before binding" {
				canonical, err := filepath.EvalSymlinks(path)
				if err != nil {
					t.Fatal(err)
				}
				name, binding = "identity-epoch/"+canonical, "identity-epoch-v1"
			}
			record, err := storage.OpenRecord(name, binding)
			if err != nil {
				t.Fatal(err)
			}
			before, err := record.Load()
			if err != nil {
				t.Fatal(err)
			}
			if err := record.Save([]byte("{")); err != nil {
				t.Fatal(err)
			}
			if err := storage.Close(); err != nil {
				t.Fatal(err)
			}
			var config Config
			if err := json.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			provider := explicitExternalProvider(t)
			if candidate, err := NewServerWithOptions(&config, zap.NewNop(), externalAttachmentOptions(provider)); candidate != nil || err == nil {
				t.Fatal("invalid durable snapshot published runtime")
			}
			_, attachedErr := provider.attached.Store()
			if (attachedErr == nil) != (phase == "portal sessions after binding") {
				t.Fatal("snapshot failure occurred on wrong side of attachment wiring")
			}
			if provider.configures != 0 || provider.closes != 0 {
				t.Fatal("snapshot failure changed provider ownership")
			}
			// The rejected candidate releases its state lock. Restore the fixture's
			// exact saved record, then use a fresh provider for a valid new root.
			storage, err = state.Open(config.State)
			if err != nil {
				t.Fatal(err)
			}
			record, err = storage.OpenRecord(name, binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := record.Save(before); err != nil {
				t.Fatal(err)
			}
			if err := storage.Close(); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			root, err = NewServerWithOptions(&config, zap.NewNop(), externalAttachmentOptions(explicitExternalProvider(t)))
			if err != nil {
				t.Fatal("repaired snapshot did not recover with fresh provider", err)
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
