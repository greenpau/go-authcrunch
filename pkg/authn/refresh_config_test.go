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
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/ids"
)

func TestRefreshConfig(t *testing.T) {
	valid := func() *RefreshConfig {
		return &RefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://auth.example.test", BasePath: "/auth"}
	}
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.AccessLifetimeSeconds != 300 || c.IdleTimeoutSeconds != 1800 || c.AbsoluteTimeoutSeconds != 28800 || c.BodyTransportEnabled || !strings.HasPrefix(c.CookieName, "__Secure-") {
		t.Fatal("invalid defaults")
	}
	if err := (*RefreshConfig)(nil).Validate(); err != nil {
		t.Fatal(err)
	}
	disabled := &RefreshConfig{}
	if err := disabled.Validate(); err != nil || disabled.AccessLifetimeSeconds != 0 {
		t.Fatal("disabled configuration changed")
	}
	cases := []struct {
		name string
		edit func(*RefreshConfig)
	}{
		{"http", func(c *RefreshConfig) { c.PublicOrigin = "http://auth.example.test" }},
		{"origin path", func(c *RefreshConfig) { c.PublicOrigin += "/auth" }},
		{"origin userinfo", func(c *RefreshConfig) { c.PublicOrigin = "https://user@auth.example.test" }},
		{"origin query", func(c *RefreshConfig) { c.PublicOrigin += "?" }},
		{"origin fragment", func(c *RefreshConfig) { c.PublicOrigin += "#fragment" }},
		{"empty realms", func(c *RefreshConfig) { c.Realms = nil }},
		{"duplicate realms", func(c *RefreshConfig) { c.Realms = []string{"local", "local"} }},
		{"empty realm", func(c *RefreshConfig) { c.Realms = []string{""} }},
		{"relative mount", func(c *RefreshConfig) { c.BasePath = "auth" }},
		{"duplicate slash", func(c *RefreshConfig) { c.BasePath = "//auth" }},
		{"dot mount", func(c *RefreshConfig) { c.BasePath = "/auth/../other" }},
		{"encoded mount", func(c *RefreshConfig) { c.BasePath = "/auth%2fother" }},
		{"backslash mount", func(c *RefreshConfig) { c.BasePath = "/auth\\other" }},
		{"cookie name", func(c *RefreshConfig) { c.CookieName = "refresh" }},
		{"cookie injection", func(c *RefreshConfig) { c.CookieName = "__Secure-test;domain=example.test" }},
		{"host prefix scoped path", func(c *RefreshConfig) { c.CookieName = "__Host-refresh" }},
		{"negative lifetime", func(c *RefreshConfig) { c.AccessLifetimeSeconds = -1 }},
		{"access exceeds absolute", func(c *RefreshConfig) { c.AccessLifetimeSeconds = 40000 }},
		{"idle exceeds absolute", func(c *RefreshConfig) { c.IdleTimeoutSeconds = 40000 }},
		{"absolute too large", func(c *RefreshConfig) { c.AbsoluteTimeoutSeconds = maxRefreshTimeout + 1 }},
		{"capacity", func(c *RefreshConfig) { c.MaxSessions = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.edit(c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	c = valid()
	c.BasePath = "/"
	c.CookieName = "__Host-refresh"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRealmWiring(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	for _, scenario := range []string{"missing", "ambiguous"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := *f.portal.config
			refreshConfig := *cfg.RefreshTokens
			cfg.RefreshTokens = &refreshConfig
			if scenario == "missing" {
				refreshConfig.Realms = []string{"unknown"}
			} else {
				cfg.IdentityStores = []string{"localdb", "localdb"}
			}
			p, err := NewPortal(PortalParameters{Config: &cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{f.store}})
			if err == nil {
				p.Close()
				t.Fatal("ambiguous or missing realm accepted")
			}
		})
	}
}

func TestPortalRefreshClose(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	login := f.login(t, "cookie")
	decodeAuth(t, login)
	credential := responseCookie(t, login, f.portal.config.RefreshTokens.CookieName)
	f.portal.Close()
	f.portal.Close()
	if w := f.request(t, "POST", "/auth/api/refresh_token", "{}", true, credential); w.Code != 503 {
		t.Fatalf("closed portal refreshed: %d", w.Code)
	}
	if w := f.request(t, "POST", "/auth/api/logout", "{}", true, credential); w.Code != 503 {
		t.Fatal("unavailable revocation reported success")
	}
}
