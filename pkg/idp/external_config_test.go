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

package idp_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp"
)

func TestExternalIdentityProviderConfig(t *testing.T) {
	cfg, err := idp.NewExternalIdentityProviderConfig("tickets", "sqlite-ticket", "ticket", "application", map[string]string{"path": "/private/tickets.db", "timeout": "1s"})
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := idp.NewExternalIdentityProviderConfig("tickets", "sqlite-ticket", "ticket", "application", map[string]string{"timeout": "1s", "path": "/private/tickets.db"})
	if err != nil || cfg.ConfigDigest != equivalent.ConfigDigest {
		t.Fatal("unstable normalized configuration binding", err)
	}
	changed, err := idp.NewExternalIdentityProviderConfig("tickets", "sqlite-ticket", "ticket", "application", map[string]string{"path": "/other/tickets.db", "timeout": "1s"})
	if err != nil || cfg.ConfigDigest == changed.ConfigDigest {
		t.Fatal("backend change did not change binding", err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tickets.db") {
		t.Fatal("descriptor exposes backend configuration")
	}
	var restored idp.ExternalIdentityProviderConfig
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored != *cfg || restored.Validate() != nil {
		t.Fatal("descriptor round trip failed")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*idp.ExternalIdentityProviderConfig)
	}{
		{"empty name", func(c *idp.ExternalIdentityProviderConfig) { c.Name = "" }},
		{"invalid name", func(c *idp.ExternalIdentityProviderConfig) { c.Name = " tickets" }},
		{"invalid realm", func(c *idp.ExternalIdentityProviderConfig) { c.Realm = "application\n" }},
		{"invalid driver", func(c *idp.ExternalIdentityProviderConfig) { c.Driver = "ticket\n" }},
		{"missing driver", func(c *idp.ExternalIdentityProviderConfig) { c.Driver = "" }},
		{"invalid kind", func(c *idp.ExternalIdentityProviderConfig) { c.Kind = "" }},
		{"oauth masquerade", func(c *idp.ExternalIdentityProviderConfig) { c.Kind = "oauth" }},
		{"saml masquerade", func(c *idp.ExternalIdentityProviderConfig) { c.Kind = "saml" }},
		{"missing digest", func(c *idp.ExternalIdentityProviderConfig) { c.ConfigDigest = "" }},
		{"uppercase digest", func(c *idp.ExternalIdentityProviderConfig) { c.ConfigDigest = strings.ToUpper(c.ConfigDigest) }},
		{"short digest", func(c *idp.ExternalIdentityProviderConfig) { c.ConfigDigest = "12" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := *cfg
			tc.mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	if (*idp.ExternalIdentityProviderConfig)(nil).Validate() == nil {
		t.Fatal("nil descriptor accepted")
	}
	for _, value := range []any{nil, (*string)(nil), make(chan int)} {
		if cfg, err := idp.NewExternalIdentityProviderConfig("tickets", "sqlite-ticket", "ticket", "application", value); err == nil || cfg != nil {
			t.Fatal("invalid backend configuration accepted")
		}
	}
}
