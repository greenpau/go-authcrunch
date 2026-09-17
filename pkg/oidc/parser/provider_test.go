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

package parser_test

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func providerStatements(extra ...[]string) []string {
	args := [][]string{
		{"issuer", "https://auth.example.test/identity"},
		{"realms", "local"},
		{"signing", "key", "files", "keys/active.pem"},
		{"applications", "website"},
	}
	args = append(args, extra...)
	statements := make([]string, len(args))
	for i, tokens := range args {
		statements[i] = cfgutil.EncodeArgs(tokens)
	}
	return statements
}

func providerApplications() map[string]*oidc.ClientConfig {
	return map[string]*oidc.ClientConfig{
		"website":     {ClientID: "web-client-id", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://web.example.test/callback"}},
		"desktop app": {ClientID: "native-client-id", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1:8400/callback"}},
		// Unselected applications must not be validated or implicitly registered.
		"unselected": nil,
	}
}

func TestNewOIDCProviderConfigFromDirectives(t *testing.T) {
	applications := providerApplications()
	before, err := json.Marshal(applications)
	if err != nil {
		t.Fatal(err)
	}
	config, err := oidcparser.NewOIDCProviderConfigFromDirectives(providerStatements(), applications)
	if err != nil {
		t.Fatal(err)
	}
	expected := &oidc.Config{
		Enabled: true, Issuer: "https://auth.example.test/identity", Realms: []string{"local"},
		SigningKeyFiles: []string{"keys/active.pem"},
		Clients: []*oidc.ClientConfig{{ClientID: "web-client-id", ClientName: "web-client-id", ClientSecret: strings.Repeat("s", 32),
			TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{"https://web.example.test/callback"}, Scopes: []string{"openid", "profile", "email"}}},
		SessionLifetimeSeconds: 28800, TokenLifetimeSeconds: 300, RefreshLifetimeSeconds: 28800, MaxRefreshTokens: 10000, MaxSessions: 10000, MaxPendingRequests: 1024, MaxGrants: 10000,
	}
	if !cmp.Equal(config, expected) {
		t.Fatal("provider defaults or selected registration differ")
	}
	after, err := json.Marshal(applications)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("parser normalized caller-owned registrations")
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored oidc.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(config, &restored) {
		t.Fatal("provider configuration did not survive JSON roundtrip")
	}
}

func TestOIDCProviderDirectiveValues(t *testing.T) {
	statements := providerStatements(
		[]string{"enabled"}, []string{"session", "lifetime", "7200"}, []string{"token", "lifetime", "120"},
		[]string{"max", "sessions", "7"}, []string{"max", "pending", "requests", "8"}, []string{"max", "grants", "9"},
	)
	statements[1] = cfgutil.EncodeArgs([]string{"realms", "local", "staff"})
	keys := []string{`keys/active "signer".pem`, "keys/previous.pem"}
	statements[2] = cfgutil.EncodeArgs(append([]string{"signing", "key", "files"}, keys...))
	statements[3] = cfgutil.EncodeArgs([]string{"applications", "desktop app", "website"})
	config, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, providerApplications())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.SessionLifetimeSeconds != 7200 || config.TokenLifetimeSeconds != 120 ||
		config.MaxSessions != 7 || config.MaxPendingRequests != 8 || config.MaxGrants != 9 ||
		!cmp.Equal(config.Realms, []string{"local", "staff"}) || !cmp.Equal(config.SigningKeyFiles, keys) {
		t.Fatal("provider settings were not preserved")
	}
	if len(config.Clients) != 2 || config.Clients[0].ClientID != "native-client-id" || config.Clients[1].ClientID != "web-client-id" ||
		!config.Clients[0].RequirePKCE || config.Clients[1].RequirePKCE || config.Clients[0].ClientSecret != "" {
		t.Fatal("application order or validated authentication policy changed")
	}
}

func TestOIDCProviderDirectiveSyntax(t *testing.T) {
	cases := []struct{ name, statement, want string }{
		{"empty", "", "invalid oidc provider directive"},
		{"blank", "   ", "invalid oidc provider directive"},
		{"unknown", "unknown SENSITIVE_VALUE", "unsupported"},
		{"unknown multiword", "signing key secret SENSITIVE_VALUE", "unsupported"},
		{"client settings", "client_secret SENSITIVE_VALUE", "unsupported"},
		{"underscore", "session_lifetime 10", "unsupported"},
		{"header", "oidc provider {", "unsupported"},
		{"brace", "}", "unsupported"},
		{"quoted keyword", `"session lifetime" 20`, "unsupported"},
		{"quoted partial keyword", `max "pending requests" 20`, "unsupported"},
		{"unfinished keyword", "signing key", "invalid"},
		{"unfinished max", "max pending", "invalid"},
		{"malformed quote", `issuer "SENSITIVE_VALUE`, "invalid"},
		{"newline", "enabled\nSENSITIVE_VALUE", "invalid"},
		{"carriage return", "enabled\rSENSITIVE_VALUE", "invalid"},
		{"boolean", "enabled true", "does not take arguments"},
		{"boolean zero", "disabled 0", "does not take arguments"},
		{"state conflict", "disabled", "duplicate"},
		{"unknown token setting", "token secret SENSITIVE_VALUE", "unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statements := providerStatements([]string{"enabled"})
			assertOIDCProviderParseError(t, append(statements, tc.statement), providerApplications(), tc.want)
		})
	}
	for _, tokens := range [][]string{
		{"issuer"}, {"realms"}, {"signing", "key", "files"}, {"applications"},
		{"session", "lifetime"}, {"token", "lifetime"}, {"max", "sessions"}, {"max", "pending", "requests"}, {"max", "grants"},
	} {
		name := strings.Join(tokens, " ")
		t.Run(name, func(t *testing.T) {
			assertOIDCProviderParseError(t, []string{cfgutil.EncodeArgs(tokens)}, providerApplications(), "argument count")
			assertOIDCProviderParseError(t, []string{cfgutil.EncodeArgs(tokens) + ` ""`}, providerApplications(), "empty")
			value := "SENSITIVE_VALUE"
			if tokens[0] == "session" || tokens[0] == "token" || tokens[0] == "max" {
				value = "10"
			}
			line := cfgutil.EncodeArgs(append(tokens, value))
			assertOIDCProviderParseError(t, []string{line, line}, providerApplications(), "duplicate")
			if tokens[0] != "realms" && tokens[0] != "signing" && tokens[0] != "applications" {
				assertOIDCProviderParseError(t, []string{line + " extra"}, providerApplications(), "argument count")
			}
		})
	}
}

func TestOIDCProviderDirectiveValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		index int
		args  []string
		want  string
	}{
		{"issuer", 0, []string{"issuer", "http://auth.example.test"}, "canonical HTTPS"},
		{"realm duplicate", 1, []string{"realms", "local", "local"}, "distinct realms"},
		{"key duplicate", 2, []string{"signing", "key", "files", "key.pem", "key.pem"}, "dedicated RSA"},
		{"missing issuer", 0, nil, "canonical HTTPS"},
		{"missing realms", 1, nil, "distinct realms"},
		{"missing keys", 2, nil, "dedicated RSA"},
		{"missing applications", 3, nil, "registered clients"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statements := providerStatements()
			if tc.args == nil {
				statements = append(statements[:tc.index], statements[tc.index+1:]...)
			} else {
				statements[tc.index] = cfgutil.EncodeArgs(tc.args)
			}
			assertOIDCProviderParseError(t, statements, providerApplications(), tc.want)
		})
	}
	assertOIDCProviderParseError(t, nil, providerApplications(), "canonical HTTPS")
	for _, setting := range []struct {
		key     string
		maximum int
		get     func(*oidc.Config) int
	}{
		{"session lifetime", 86400, func(c *oidc.Config) int { return c.SessionLifetimeSeconds }},
		{"token lifetime", 3600, func(c *oidc.Config) int { return c.TokenLifetimeSeconds }},
		{"max sessions", 1000000, func(c *oidc.Config) int { return c.MaxSessions }},
		{"max pending requests", 100000, func(c *oidc.Config) int { return c.MaxPendingRequests }},
		{"max grants", 1000000, func(c *oidc.Config) int { return c.MaxGrants }},
	} {
		t.Run(setting.key, func(t *testing.T) {
			for _, value := range []string{"0", "1", strconv.Itoa(setting.maximum)} {
				config, err := oidcparser.NewOIDCProviderConfigFromDirectives(providerStatements(append(strings.Fields(setting.key), value)), providerApplications())
				if err != nil {
					t.Fatal(err)
				}
				expected, _ := strconv.Atoi(value)
				if (expected == 0 && setting.get(config) <= 0) || (expected != 0 && setting.get(config) != expected) {
					t.Fatal("integer boundary not preserved")
				}
			}
			for _, value := range []string{"-1", strconv.Itoa(setting.maximum + 1), "99999999999999999999999999999", "1.5", "5m", "SENSITIVE_VALUE"} {
				assertOIDCProviderParseError(t, providerStatements(append(strings.Fields(setting.key), value)), providerApplications(), "oidc")
			}
		})
	}
}

func TestOIDCProviderApplicationResolution(t *testing.T) {
	for _, tc := range []struct {
		name       string
		references []string
		modify     func(map[string]*oidc.ClientConfig)
		want       string
	}{
		{"unknown", []string{"missing"}, nil, "unregistered"},
		{"no fallback to client ID", []string{"web-client-id"}, nil, "unregistered"},
		{"nil", []string{"unselected"}, nil, "client is nil"},
		{"duplicate reference", []string{"website", "website"}, nil, "duplicate oidc application reference"},
		{"duplicate IDs", []string{"website", "alias"}, func(m map[string]*oidc.ClientConfig) { m["alias"] = m["website"] }, "duplicate oidc client_id"},
		{"missing ID", []string{"website"}, func(m map[string]*oidc.ClientConfig) { m["website"].ClientID = "" }, "invalid oidc client_id"},
		{"missing secret", []string{"website"}, func(m map[string]*oidc.ClientConfig) { m["website"].ClientSecret = "" }, "secrets require"},
		{"invalid redirect", []string{"website"}, func(m map[string]*oidc.ClientConfig) { m["website"].RedirectURIs = []string{"http://SENSITIVE_VALUE"} }, "requires HTTPS"},
		{"invalid nickname", []string{" website"}, nil, "invalid oidc application reference"},
		{"tab nickname", []string{"web\tsite"}, nil, "invalid oidc application reference"},
		{"long nickname", []string{strings.Repeat("x", 257)}, nil, "invalid oidc application reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applications := providerApplications()
			if tc.modify != nil {
				tc.modify(applications)
			}
			before, err := json.Marshal(applications)
			if err != nil {
				t.Fatal(err)
			}
			statements := providerStatements()
			statements[3] = cfgutil.EncodeArgs(append([]string{"applications"}, tc.references...))
			assertOIDCProviderParseError(t, statements, applications, tc.want)
			// Explicit references also fail closed when final validation opts out.
			assertOIDCProviderParseError(t, append(statements, "disabled"), applications, tc.want)
			after, err := json.Marshal(applications)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("failed resolution mutated registration inputs")
			}
		})
	}
	assertOIDCProviderParseError(t, providerStatements(), nil, "unregistered")
}

func TestOIDCProviderDirectivesDisabled(t *testing.T) {
	for _, statements := range [][]string{{"disabled"}, {"issuer http://unused", "max sessions -1", "disabled"}} {
		config, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, nil)
		if err != nil {
			t.Fatal(err)
		}
		if config == nil || config.Enabled || len(config.Clients) != 0 {
			t.Fatal("disabled configuration changed")
		}
	}
	assertOIDCProviderParseError(t, []string{"disabled", "disabled"}, nil, "duplicate")
	assertOIDCProviderParseError(t, []string{"disabled", "max sessions true"}, nil, "invalid oidc provider integer")
}

func TestOIDCProviderDirectivesIndependent(t *testing.T) {
	applications := providerApplications()
	applications["website"].Scopes = []string{"openid", "email"}
	statements := providerStatements()
	const count = 16
	configs := make([]*oidc.Config, count)
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() {
			config, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, applications)
			if err != nil {
				t.Error(err)
				return
			}
			configs[i] = config
			config.Clients[0].ClientName = "local copy"
		})
	}
	workers.Wait()
	if applications["website"].ClientName != "" {
		t.Fatal("concurrent parsing modified registrations")
	}
	for _, config := range configs {
		if config == nil {
			t.Fatal("missing concurrent result")
		}
	}
	configs[0].Clients[0].RedirectURIs[0] = "https://changed.example.test"
	configs[0].Clients[0].Scopes[0] = "changed"
	configs[0].Realms[0] = "changed"
	configs[0].SigningKeyFiles[0] = "changed"
	if applications["website"].RedirectURIs[0] != "https://web.example.test/callback" || applications["website"].Scopes[0] != "openid" {
		t.Fatal("result shares registration storage")
	}
	for _, config := range configs[1:] {
		if config.Clients[0].RedirectURIs[0] != "https://web.example.test/callback" || config.Clients[0].Scopes[0] != "openid" || config.Realms[0] != "local" || config.SigningKeyFiles[0] != "keys/active.pem" {
			t.Fatal("parser results share mutable storage")
		}
	}
}

func assertOIDCProviderParseError(t *testing.T, statements []string, applications map[string]*oidc.ClientConfig, want string) {
	t.Helper()
	config, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, applications)
	if config != nil || err == nil {
		t.Fatal("invalid provider directives returned configuration or no error")
	}
	if strings.Contains(err.Error(), "SENSITIVE_VALUE") {
		t.Fatal("parser error disclosed a supplied value")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %s; expected %s", err, want)
	}
}
