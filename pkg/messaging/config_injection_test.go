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

package messaging

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type injectedTestProvider struct {
	kind    string
	invalid bool
}

func (p *injectedTestProvider) Validate() error {
	if p.invalid {
		return errors.New("private backend secret")
	}
	return nil
}
func (p *injectedTestProvider) Kind() string          { return p.kind }
func (p *injectedTestProvider) AsMap() map[string]any { return nil }
func (p *injectedTestProvider) Send(*SendInput) error { return nil }
func TestInjectedMessagingConfiguration(t *testing.T) {
	p := &injectedTestProvider{kind: "custom"}
	cfg := &Config{}
	if err := cfg.AddProvider("outbox", p); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddProvider("outbox", p); err == nil {
		t.Fatal("duplicate accepted")
	}
	p.invalid = true
	if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("backend validation/redaction", err)
	}
	p.invalid = false
	raw, _ := json.Marshal(cfg)
	if strings.Contains(string(raw), "outbox") || strings.Contains(string(raw), "custom") {
		t.Fatal("runtime provider serialized")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.ExtractProvider("outbox") != p {
		t.Fatal("validation discarded provider")
	}
	cfg.Add([]string{"kind file", "name outbox", "root_dir /tmp/example", "sender auth@example.test"})
	if err := cfg.Validate(); err == nil || err.Error() != "duplicate messaging provider name" {
		t.Fatal("raw config collision validation", err)
	}
	if cfg.ExtractProvider("outbox") != p {
		t.Fatal("failure mutated binding")
	}
	for _, kind := range []string{"", "email", "file", "unknown"} {
		if err := (&Config{}).AddProvider("fixture", &injectedTestProvider{kind: kind}); err == nil {
			t.Fatal("reserved kind accepted", kind)
		}
	}
	for _, name := range []string{"", " bad", "bad\n", "\xff"} {
		if err := (&Config{}).AddProvider(name, p); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
	var nilConfig *Config
	if nilConfig.FindProvider("x") || nilConfig.ExtractProvider("x") != nil || nilConfig.GetProviderType("x") != UnknownMessagingProviderKindLabel || nilConfig.AddProvider("x", p) == nil {
		t.Fatal("nil config handling")
	}
	cfg = &Config{FileProviders: []*FileProvider{{Name: "fixture"}}}
	if err := cfg.AddProvider("fixture", p); err == nil {
		t.Fatal("concrete collision accepted")
	}
}

func TestNativeMessagingConfiguration(t *testing.T) {
	fresh := func() *Config {
		return &Config{EmailProviders: []*EmailProvider{{Name: "email", Address: "localhost:25", Protocol: "smtp", Passwordless: true, SenderEmail: "auth@example.test"}}, FileProviders: []*FileProvider{{Name: "file", RootDir: "/private/output", SenderEmail: "auth@example.test"}}}
	}
	cfg := fresh()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored Config
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	queue := &injectedTestProvider{kind: "sqlite"}
	if err := restored.AddProvider("queue", queue); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := restored.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if restored.ExtractEmailProvider("email") == nil || restored.ExtractFileProvider("file") == nil || restored.ExtractProvider("queue") != queue {
		t.Fatal("native validation discarded providers")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"nil email", func(c *Config) { c.EmailProviders[0] = nil }},
		{"nil file", func(c *Config) { c.FileProviders[0] = nil }},
		{"invalid email", func(c *Config) { c.EmailProviders[0].SenderEmail = "" }},
		{"invalid file", func(c *Config) { c.FileProviders[0].RootDir = "" }},
		{"duplicate email", func(c *Config) { c.EmailProviders = append(c.EmailProviders, c.EmailProviders[0]) }},
		{"cross-kind duplicate", func(c *Config) { c.FileProviders[0].Name = "email" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := fresh()
			tc.mutate(candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid native providers accepted")
			}
		})
	}
	cfg = fresh()
	cfg.Add([]string{"kind file", "name replacement", "root_dir /private/replacement", "sender auth@example.test"})
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.FindProvider("email") || cfg.FindProvider("file") || !cfg.FindProvider("replacement") {
		t.Fatal("raw instructions lost authority")
	}
	cfg.Add([]string{"kind email", "name replacement", "address localhost:25", "protocol smtp", "sender auth@example.test", "passwordless"})
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate raw provider accepted")
	}
	if cfg.ExtractFileProvider("replacement") == nil {
		t.Fatal("failed validation discarded previous providers")
	}
	if (*Config)(nil).Validate() == nil {
		t.Fatal("nil configuration accepted")
	}
}
