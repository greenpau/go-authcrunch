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
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewTokenRefreshConfigFromDirectives(t *testing.T) {
	minimal := []string{"realms local", "public origin https://auth.example.test", "base path /auth"}
	defaults := &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://auth.example.test", BasePath: "/auth"}
	if err := defaults.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		statements []string
		want       *authn.TokenRefreshConfig
	}{
		{"defaults", minimal, defaults},
		{"explicit zeros", append(slices.Clone(minimal), "access lifetime 0", "idle timeout 0", "absolute timeout 0", "max sessions 0", "max rotations 0"), defaults},
		{"all settings", []string{
			"enabled", cfgutil.EncodeArgs([]string{"realms", "local", "second store"}),
			"public origin https://auth.example.test:8443", "base path /tenant/auth",
			"cookie name CUSTOM_REFRESH_TOKEN", "access lifetime 60",
			"idle timeout 120", "absolute timeout 240",
			"body transport enabled", "max sessions 7", "max rotations 3",
		}, &authn.TokenRefreshConfig{
			Enabled: true, Realms: []string{"local", "second store"}, PublicOrigin: "https://auth.example.test:8443",
			BasePath: "/tenant/auth", CookieName: "CUSTOM_REFRESH_TOKEN", AccessLifetimeSeconds: 60,
			IdleTimeoutSeconds: 120, AbsoluteTimeoutSeconds: 240, BodyTransportEnabled: true, MaxSessions: 7, MaxRotations: 3,
		}},
		{"root mount", []string{
			"realms local", "public origin https://auth.example.test", "base path /",
			"cookie name ROOT_REFRESH_TOKEN", "body transport disabled",
		}, &authn.TokenRefreshConfig{
			Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://auth.example.test", BasePath: "/",
			CookieName: "ROOT_REFRESH_TOKEN", AccessLifetimeSeconds: 300, IdleTimeoutSeconds: 1800,
			AbsoluteTimeoutSeconds: 28800, MaxSessions: 10000, MaxRotations: 1024,
		}},
		{"disabled", []string{"disabled"}, &authn.TokenRefreshConfig{}},
		{"disabled validation unchanged", []string{"disabled", "public origin http://example.test", "max sessions -1"}, &authn.TokenRefreshConfig{PublicOrigin: "http://example.test", MaxSessions: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.statements)
			got, err := refreshparser.NewTokenRefreshConfigFromDirectives(tc.statements)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("config mismatch (-want +got):\n%s", diff)
			}
			if !slices.Equal(before, tc.statements) {
				t.Fatal("constructor mutated input statements")
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var restored authn.TokenRefreshConfig
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := restored.Validate(); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(got, &restored); diff != "" {
				t.Fatalf("JSON round trip changed config:\n%s", diff)
			}
		})
	}
	for _, state := range []string{"enabled", "disabled"} {
		for _, body := range []string{"enabled", "disabled"} {
			t.Run("state/"+state+"/body/"+body, func(t *testing.T) {
				got, err := refreshparser.NewTokenRefreshConfigFromDirectives(append(slices.Clone(minimal), state, "body transport "+body))
				if err != nil || got.Enabled != (state == "enabled") || got.BodyTransportEnabled != (body == "enabled") {
					t.Fatalf("state parsing failed: %v", err)
				}
			})
		}
	}
}

func TestNewTokenRefreshConfigFromDirectivesGrammar(t *testing.T) {
	// A disabled config still rejects bad grammar, before semantic validation.
	for _, key := range []string{"realms", "public origin", "base path", "cookie name", "access lifetime", "idle timeout", "absolute timeout", "max sessions", "max rotations"} {
		value := "synthetic-value"
		switch key {
		case "access lifetime", "idle timeout", "absolute timeout", "max sessions", "max rotations":
			value = "1"
		}
		for _, kind := range []string{"missing", "empty", "extra", "duplicate"} {
			if key == "realms" && kind == "extra" {
				continue
			}
			t.Run(key+"/"+kind, func(t *testing.T) {
				statements := []string{"disabled"}
				switch kind {
				case "missing":
					statements = append(statements, key)
				case "empty":
					// EncodeArgs trims a trailing empty field; preserve the empty
					// CSV value explicitly so this differs from a missing value.
					statements = append(statements, key+` ""`)
				case "extra":
					statements = append(statements, cfgutil.EncodeArgs(append(strings.Fields(key), value, value)))
				case "duplicate":
					line := cfgutil.EncodeArgs(append(strings.Fields(key), value))
					statements = append(statements, line, line)
				}
				if got, err := refreshparser.NewTokenRefreshConfigFromDirectives(statements); err == nil || got != nil {
					t.Fatal("malformed setting did not fail atomically")
				}
			})
		}
	}
	for _, line := range []string{
		"", "   ", "unknown synthetic-sensitive-value", "REALMS local", "base path \"unterminated",
		"base path /auth\nmax sessions 3", "base path /auth\r", "realms local \"\"",
		"body transport maybe", "body transport", "body", "enabled maybe", "disabled false",
		"public", "public host https://example.test", "public origin", "base", "base path", "cookie",
		"access", "idle", "absolute", "max", "max session 1",
		"body transport enabled extra", "body transport enabled\nbody transport disabled",
		"\"public origin\" https://auth.example.test", "public \"origin https://auth.example.test\"",
		"public_origin https://auth.example.test", "base_path /auth", "cookie_name CUSTOM_REFRESH_TOKEN",
		"access_lifetime_seconds 300", "idle_timeout_seconds 1800", "absolute_timeout_seconds 28800",
		"body_transport_enabled true", "max_sessions 1", "max_rotations 1", "max sessions 1.5", "idle timeout 5m",
		"max sessions 999999999999999999999999999999999", "max rotations 0x10",
		"access lifetime NaN", "absolute timeout \" 60 \"",
	} {
		t.Run(fmt.Sprintf("line %q", line), func(t *testing.T) {
			got, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"disabled", line})
			if err == nil || got != nil {
				t.Fatal("malformed statement accepted")
			}
			if strings.Contains(err.Error(), "synthetic-sensitive-value") {
				t.Fatal("parser echoed unsupported input")
			}
		})
	}
}

func TestNewTokenRefreshConfigFromDirectivesValidation(t *testing.T) {
	for _, tc := range []struct {
		key, value, want string
	}{
		{"public origin", "http://auth.example.test", "refresh public_origin"},
		{"public origin", "https://auth.example.test/auth", "refresh public_origin"},
		{"public origin", "{env.ORIGIN}", "refresh public_origin"},
		{"base path", "/auth/../other", "refresh base_path"},
		{"cookie name", "INVALID;REFRESH_TOKEN", "invalid refresh cookie name"},
		{"realms", " local ", "invalid or duplicate refresh realm"},
		{"access lifetime", "-1", "invalid refresh lifetime bounds"},
		{"access lifetime", "28801", "invalid refresh lifetime bounds"},
		{"idle timeout", "28801", "invalid refresh lifetime bounds"},
		{"absolute timeout", "2592001", "invalid refresh lifetime bounds"},
		{"max sessions", "-1", "refresh capacity limits must be positive"},
		{"max rotations", "-1", "refresh capacity limits must be positive"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			var statements []string
			for key, value := range map[string]string{"public origin": "https://auth.example.test", "base path": "/auth", "realms": "local"} {
				if key != tc.key {
					statements = append(statements, cfgutil.EncodeArgs(append(strings.Fields(key), value)))
				}
			}
			statements = append(statements, cfgutil.EncodeArgs(append(strings.Fields(tc.key), tc.value)))
			got, err := refreshparser.NewTokenRefreshConfigFromDirectives(statements)
			if err == nil || got != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want validation error %q, got %v", tc.want, err)
			}
		})
	}
	for _, statements := range [][]string{
		nil, {}, {"base path /auth", "realms local"},
		{"public origin https://auth.example.test", "realms local"},
		{"public origin https://auth.example.test", "base path /auth"},
		{"public origin https://auth.example.test", "base path /auth", "realms local local"},
	} {
		if got, err := refreshparser.NewTokenRefreshConfigFromDirectives(statements); err == nil || got != nil {
			t.Fatal("incomplete or ambiguous enabled configuration accepted")
		}
	}
}

func TestNewTokenRefreshConfigFromDirectivesStates(t *testing.T) {
	for _, first := range []string{"enabled", "disabled"} {
		for _, second := range []string{"enabled", "disabled"} {
			for _, prefix := range []string{"", "body transport "} {
				t.Run(prefix+first+"/"+second, func(t *testing.T) {
					got, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{prefix + first, prefix + second})
					if err == nil || got != nil || !strings.Contains(err.Error(), "duplicate token refresh directive") {
						t.Fatalf("repeated or conflicting states did not fail as duplicates: %v", err)
					}
				})
			}
		}
	}
	for _, value := range []string{"true", "false", "1", "0", "on", "off", "yes", "no", "ENABLED", "DISABLED", "synthetic-sensitive-value"} {
		for _, prefix := range []string{"enabled ", "disabled ", "body transport "} {
			t.Run(prefix+value, func(t *testing.T) {
				got, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{prefix + value})
				if err == nil || got != nil {
					t.Fatal("invalid state accepted")
				}
				if strings.Contains(err.Error(), "synthetic-sensitive-value") {
					t.Fatal("state parser echoed an invalid value")
				}
			})
		}
	}
}

func TestNewTokenRefreshConfigFromDirectivesIndependentConfigurations(t *testing.T) {
	statements := []string{"realms local", "public origin https://auth.example.test", "base path /auth"}
	for i := range 16 {
		t.Run(fmt.Sprintf("consumer %d", i), func(t *testing.T) {
			t.Parallel()
			first, err := refreshparser.NewTokenRefreshConfigFromDirectives(statements)
			if err != nil {
				t.Fatal(err)
			}
			second, err := refreshparser.NewTokenRefreshConfigFromDirectives(statements)
			if err != nil {
				t.Fatal(err)
			}
			first.Realms[0] = "another-store"
			first.Enabled = false
			if !second.Enabled || !slices.Equal(second.Realms, []string{"local"}) || statements[0] != "realms local" {
				t.Fatal("independent consumers share mutable parser state")
			}
		})
	}
}

func ExampleNewTokenRefreshConfigFromDirectives() {
	config, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"realms", "local"}),
		cfgutil.EncodeArgs([]string{"public", "origin", "https://auth.example.test"}),
		cfgutil.EncodeArgs([]string{"base", "path", "/auth"}),
		cfgutil.EncodeArgs([]string{"body", "transport", "enabled"}),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	portal := authn.PortalConfig{RefreshTokens: config}
	fmt.Println(portal.RefreshTokens.Enabled, portal.RefreshTokens.BasePath, portal.RefreshTokens.BodyTransportEnabled)
	// Output: true /auth true
}
