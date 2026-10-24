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

package registry_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/registry"
)

func TestExternalUserRegistryConfig(t *testing.T) {
	cfg, err := registry.NewExternalUserRegistryConfig("signup", "sqlite", "accounts", "staff", "mail", map[string]string{"path": "/private/accounts.db", "timeout": "1s"})
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := registry.NewExternalUserRegistryConfig("signup", "sqlite", "accounts", "staff", "mail", map[string]string{"timeout": "1s", "path": "/private/accounts.db"})
	if err != nil || cfg.ConfigDigest != equivalent.ConfigDigest {
		t.Fatal("unstable normalized configuration binding", err)
	}
	changed, err := registry.NewExternalUserRegistryConfig("signup", "sqlite", "accounts", "staff", "mail", map[string]string{"path": "/other/accounts.db", "timeout": "1s"})
	if err != nil || cfg.ConfigDigest == changed.ConfigDigest {
		t.Fatal("backend change did not change binding", err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "accounts.db") {
		t.Fatal("descriptor exposes backend configuration")
	}
	var restored registry.ExternalUserRegistryConfig
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored != *cfg || restored.Validate() != nil {
		t.Fatal("descriptor round trip failed")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*registry.ExternalUserRegistryConfig)
	}{
		{"empty name", func(c *registry.ExternalUserRegistryConfig) { c.Name = "" }},
		{"invalid name", func(c *registry.ExternalUserRegistryConfig) { c.Name = " accounts" }},
		{"invalid realm", func(c *registry.ExternalUserRegistryConfig) { c.Realm = "staff\n" }},
		{"invalid kind", func(c *registry.ExternalUserRegistryConfig) { c.Kind = "" }},
		{"local masquerade", func(c *registry.ExternalUserRegistryConfig) { c.Kind = "local" }},
		{"unknown masquerade", func(c *registry.ExternalUserRegistryConfig) { c.Kind = "unknown" }},
		{"missing store", func(c *registry.ExternalUserRegistryConfig) { c.IdentityStore = "" }},
		{"missing email", func(c *registry.ExternalUserRegistryConfig) { c.EmailProvider = "" }},
		{"missing digest", func(c *registry.ExternalUserRegistryConfig) { c.ConfigDigest = "" }},
		{"uppercase digest", func(c *registry.ExternalUserRegistryConfig) { c.ConfigDigest = strings.ToUpper(c.ConfigDigest) }},
		{"short digest", func(c *registry.ExternalUserRegistryConfig) { c.ConfigDigest = "12" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := *cfg
			tc.mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	if (*registry.ExternalUserRegistryConfig)(nil).Validate() == nil {
		t.Fatal("nil descriptor accepted")
	}
	for _, value := range []any{nil, (*string)(nil), make(chan int)} {
		if cfg, err := registry.NewExternalUserRegistryConfig("signup", "sqlite", "accounts", "staff", "mail", value); err == nil || cfg != nil {
			t.Fatal("invalid backend configuration accepted")
		}
	}
}
