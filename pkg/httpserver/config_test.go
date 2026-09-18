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

package httpserver

import (
	"encoding/json"
	"reflect"
	"testing"
)

func validConfig() *Config {
	return &Config{InsecureHTTP: true, Portals: []PortalRoute{{Name: "portal", Path: "/auth"}}}
}

func TestConfig(t *testing.T) {
	if err := (*Config)(nil).Validate(); err == nil {
		t.Fatal("nil config accepted")
	}
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1:8443" || cfg.ReadHeaderTimeout != "10s" || cfg.ReadTimeout != "30s" || cfg.WriteTimeout != "60s" || cfg.IdleTimeout != "120s" || cfg.ShutdownTimeout != "30s" || cfg.MaxHeaderBytes != 1<<20 {
		t.Fatal("incorrect transport defaults")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored Config
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil || !reflect.DeepEqual(cfg, &restored) {
		t.Fatal("config did not survive reload")
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{"TLS", func(c *Config) { c.InsecureHTTP = false; c.TLSCertificateFile = "cert.pem"; c.TLSKeyFile = "key.pem" }, true},
		{"TLS missing", func(c *Config) { c.InsecureHTTP = false }, false},
		{"TLS incomplete", func(c *Config) { c.InsecureHTTP = false; c.TLSCertificateFile = "cert.pem" }, false},
		{"mixed transports", func(c *Config) { c.TLSKeyFile = "key.pem" }, false},
		{"missing routes", func(c *Config) { c.Portals = nil }, false},
		{"duplicate name", func(c *Config) { c.Portals = append(c.Portals, PortalRoute{Name: "portal", Path: "/other"}) }, false},
		{"overlap", func(c *Config) { c.Portals = append(c.Portals, PortalRoute{Name: "other", Path: "/auth/other"}) }, false},
		{"root overlap", func(c *Config) { c.Portals = append(c.Portals, PortalRoute{Name: "other", Path: "/"}) }, false},
		{"siblings", func(c *Config) { c.Portals = append(c.Portals, PortalRoute{Name: "other", Path: "/authenticate"}) }, true},
		{"IPv6", func(c *Config) { c.ListenAddress = "[::1]:0" }, true},
		{"invalid address", func(c *Config) { c.ListenAddress = "localhost" }, false},
		{"invalid port", func(c *Config) { c.ListenAddress = "localhost:https" }, false},
		{"port overflow", func(c *Config) { c.ListenAddress = ":65536" }, false},
		{"negative timeout", func(c *Config) { c.ReadTimeout = "-1s" }, false},
		{"zero timeout", func(c *Config) { c.ReadHeaderTimeout = "0s" }, false},
		{"unbounded timeout", func(c *Config) { c.WriteTimeout = "25h" }, false},
		{"invalid idle", func(c *Config) { c.IdleTimeout = "invalid" }, false},
		{"invalid shutdown", func(c *Config) { c.ShutdownTimeout = "invalid" }, false},
		{"small header", func(c *Config) { c.MaxHeaderBytes = 1 }, false},
		{"large header", func(c *Config) { c.MaxHeaderBytes = 1 << 25 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.change(c)
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
	for _, mount := range []string{"", "auth", "/auth/", "/auth/../other", "/auth//other", "/a%2fb", "/a?b", "/a#b", "/a\\b", "/a\nb", "/a b", "/{name}", "/login", "/tenant/api", "/assets/sub", "/login-service", "/tenant/profile-ui", "/auth\x00", "/auth\x1f", "/auth\x7f", "/auth\u0085"} {
		t.Run("mount "+mount, func(t *testing.T) {
			cfg := validConfig()
			cfg.Portals[0].Path = mount
			if cfg.Validate() == nil {
				t.Fatal("invalid mount accepted")
			}
		})
	}
	for _, mount := range []string{"/", "/auth", "/tenant/auth"} {
		cfg := validConfig()
		cfg.Portals[0].Path = mount
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
