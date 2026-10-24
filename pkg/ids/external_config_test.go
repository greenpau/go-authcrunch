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

package ids_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/ids"
)

func TestExternalIdentityStoreConfig(t *testing.T) {
	cfg, err := ids.NewExternalIdentityStoreConfig("accounts", "sqlite", "staff", map[string]string{"path": "/private/accounts.db", "timeout": "1s"})
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := ids.NewExternalIdentityStoreConfig("accounts", "sqlite", "staff", map[string]string{"timeout": "1s", "path": "/private/accounts.db"})
	if err != nil || cfg.ConfigDigest != equivalent.ConfigDigest {
		t.Fatal("unstable normalized configuration binding", err)
	}
	changed, err := ids.NewExternalIdentityStoreConfig("accounts", "sqlite", "staff", map[string]string{"path": "/other/accounts.db", "timeout": "1s"})
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
	var restored ids.ExternalIdentityStoreConfig
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored != *cfg || restored.Validate() != nil {
		t.Fatal("descriptor round trip failed")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ids.ExternalIdentityStoreConfig)
	}{
		{"empty name", func(c *ids.ExternalIdentityStoreConfig) { c.Name = "" }},
		{"invalid name", func(c *ids.ExternalIdentityStoreConfig) { c.Name = " accounts" }},
		{"invalid realm", func(c *ids.ExternalIdentityStoreConfig) { c.Realm = "staff\n" }},
		{"invalid kind", func(c *ids.ExternalIdentityStoreConfig) { c.Kind = "" }},
		{"local masquerade", func(c *ids.ExternalIdentityStoreConfig) { c.Kind = "local" }},
		{"ldap masquerade", func(c *ids.ExternalIdentityStoreConfig) { c.Kind = "ldap" }},
		{"missing digest", func(c *ids.ExternalIdentityStoreConfig) { c.ConfigDigest = "" }},
		{"uppercase digest", func(c *ids.ExternalIdentityStoreConfig) { c.ConfigDigest = strings.ToUpper(c.ConfigDigest) }},
		{"short digest", func(c *ids.ExternalIdentityStoreConfig) { c.ConfigDigest = "12" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := *cfg
			tc.mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	if (*ids.ExternalIdentityStoreConfig)(nil).Validate() == nil {
		t.Fatal("nil descriptor accepted")
	}
	for _, value := range []any{nil, (*string)(nil), make(chan int)} {
		if cfg, err := ids.NewExternalIdentityStoreConfig("accounts", "sqlite", "staff", value); err == nil || cfg != nil {
			t.Fatal("invalid backend configuration accepted")
		}
	}
}
