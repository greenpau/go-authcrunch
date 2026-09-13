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

package oidc_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestOIDCClientConfigFromDirectives(t *testing.T) {
	const callback = "https://app.example.test/callback"
	secret := strings.Repeat("s", 32) + ` +/:,"quoted" secret `
	for _, tc := range []struct {
		name       string
		statements []string
		want       oidc.ClientConfig
	}{
		{
			name:       "minimal block",
			statements: []string{"redirect_uris " + callback},
			want:       oidc.ClientConfig{ClientName: "myapp", TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, Scopes: []string{"openid", "profile", "email"}, RequirePKCE: true},
		},
		{
			name: "explicit values and quoted tokens",
			statements: []string{
				"client_id stable-application-id",
				cfgutil.EncodeArgs([]string{"client_name", `My "quoted" application`}),
				cfgutil.EncodeArgs([]string{"client_secret", secret}),
				"token_endpoint_auth_method client_secret_post",
				"redirect_uris " + callback + " https://app.example.test/other?registered=yes",
				"scopes openid email", "require_pkce off", "skip_consent on",
			},
			want: oidc.ClientConfig{ClientID: "stable-application-id", ClientName: `My "quoted" application`, ClientSecret: secret, TokenEndpointAuthMethod: "client_secret_post", RedirectURIs: []string{callback, "https://app.example.test/other?registered=yes"}, Scopes: []string{"openid", "email"}, SkipConsent: true},
		},
		{
			name: "public client",
			statements: []string{
				"client_id desktop", "token_endpoint_auth_method none",
				"redirect_uris http://127.0.0.1:8400/callback", "scopes openid", "require_pkce true", "skip_consent false",
			},
			want: oidc.ClientConfig{ClientID: "desktop", ClientName: "myapp", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1:8400/callback"}, Scopes: []string{"openid"}, RequirePKCE: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := slices.Clone(tc.statements)
			client, err := oidc.NewClientConfigFromDirectives("myapp", tc.statements)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(original, tc.statements) {
				t.Fatal("parser changed its input")
			}
			want := tc.want
			if want.ClientID == "" {
				if len(client.ClientID) != 43 {
					t.Fatal("missing generated client ID")
				}
				want.ClientID = client.ClientID
			}
			if want.ClientSecret == "" && want.TokenEndpointAuthMethod != "none" {
				if len(client.ClientSecret) != 43 {
					t.Fatal("missing generated secret")
				}
				want.ClientSecret = client.ClientSecret
			}
			actual, _ := json.Marshal(client)
			expected, _ := json.Marshal(want)
			if !bytes.Equal(actual, expected) {
				t.Fatal("parsed registration differs from expected configuration")
			}
			// The embedder supplies persisted credentials on another adaptation.
			// Re-encoding uses the same boundary as Caddy's crypto directives.
			statements := []string{
				cfgutil.EncodeArgs([]string{"client_id", client.ClientID}),
				cfgutil.EncodeArgs([]string{"client_name", client.ClientName}),
				cfgutil.EncodeArgs([]string{"token_endpoint_auth_method", client.TokenEndpointAuthMethod}),
				cfgutil.EncodeArgs(append([]string{"redirect_uris"}, client.RedirectURIs...)),
				cfgutil.EncodeArgs(append([]string{"scopes"}, client.Scopes...)),
			}
			if client.ClientSecret != "" {
				statements = append(statements, cfgutil.EncodeArgs([]string{"client_secret", client.ClientSecret}))
			}
			if !client.RequirePKCE {
				statements = append(statements, "require_pkce false")
			}
			if client.SkipConsent {
				statements = append(statements, "skip_consent true")
			}
			restored, err := oidc.NewClientConfigFromDirectives("myapp", statements)
			if err != nil {
				t.Fatal(err)
			}
			reencoded, _ := json.Marshal(restored)
			if !bytes.Equal(actual, reencoded) {
				t.Fatal("repeated adaptation changed persisted registration")
			}
		})
	}
}

func TestOIDCClientDirectiveErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statements []string
		err        string
	}{
		{"missing directives", nil, "oidc requires distinct redirect_uris"},
		{"empty line", []string{""}, "invalid oidc application directive at line 1"},
		{"missing value", []string{"client_id"}, "invalid oidc application directive at line 1"},
		{"empty secret", []string{`client_secret ""`}, "empty oidc application directive client_secret value at line 1"},
		{"empty ID", []string{`client_id ""`}, "empty oidc application directive client_id value at line 1"},
		{"empty list value", []string{`scopes openid ""`}, "empty oidc application directive scopes value at line 1"},
		{"scalar extra values", []string{"client_id app extra"}, "oidc application directive client_id at line 1 requires one value"},
		{"unclosed quote", []string{`client_secret "unclosed`}, "invalid oidc application directive at line 1"},
		{"trailing directive", []string{"client_id app\nskip_consent true"}, "invalid oidc application directive at line 1"},
		{"CR directive", []string{"client_id app\rskip_consent true"}, "invalid oidc application directive at line 1"},
		{"duplicate ID", []string{"client_id app", "client_id other"}, "duplicate oidc application directive client_id at line 2"},
		{"duplicate scopes", []string{"scopes openid", "scopes email"}, "duplicate oidc application directive scopes at line 2"},
		{"duplicate secret", []string{"client_secret first", "client_secret second"}, "duplicate oidc application directive client_secret at line 2"},
		{"unknown directive", []string{"unknown value"}, "unsupported oidc application directive at line 1"},
		{"unsupported key registration", []string{"private_key_jwt value"}, "unsupported oidc application directive at line 1"},
		{"bad boolean", []string{"skip_consent maybe"}, "invalid oidc application boolean skip_consent at line 1"},
		{"public PKCE disabled", []string{"require_pkce false", "token_endpoint_auth_method none"}, "public oidc clients require PKCE"},
		{"short secret", []string{"client_secret short"}, "oidc client secrets require 32 to 1024 bytes"},
		{"unsupported method", []string{"token_endpoint_auth_method private_key_jwt"}, "unsupported oidc token endpoint authentication method"},
		{"public secret", []string{"token_endpoint_auth_method none", "client_secret value"}, "public oidc clients cannot have a secret"},
		{"invalid redirect", []string{"redirect_uris http://app.example.test/callback"}, "oidc redirect_uri requires HTTPS or a public client's literal loopback address"},
		{"duplicate redirect", []string{"redirect_uris https://app.example.test/callback https://app.example.test/callback"}, "oidc requires distinct redirect_uris"},
		{"invalid scope", []string{"redirect_uris https://app.example.test/callback", "scopes openid admin"}, "unsupported oidc scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := oidc.NewClientConfigFromDirectives("app", tc.statements)
			if err == nil || err.Error() != tc.err || client != nil {
				t.Fatal("directive was not rejected with expected error")
			}
		})
	}
	for _, nickname := range []string{"", " app", "app\n", "app\tname", strings.Repeat("a", 257)} {
		if client, err := oidc.NewClientConfigFromDirectives(nickname, nil); err == nil || err.Error() != "invalid oidc application nickname" || client != nil {
			t.Fatal("invalid application nickname accepted")
		}
	}
}

func TestOIDCClientDirectiveSecretRedaction(t *testing.T) {
	const secret = "unique-sensitive-value-never-in-errors"
	for _, statement := range []string{
		"client_secret " + secret + " extra",
		`client_secret "` + secret,
		"skip_consent " + secret,
		"token_endpoint_auth_method " + secret,
		secret + " value",
	} {
		if _, err := oidc.NewClientConfigFromDirectives("app", []string{statement}); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("invalid directive leaked sensitive content or succeeded")
		}
	}
}

func TestOIDCClientDirectiveBooleans(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true}, {"yes", true}, {"on", true}, {"1", true}, {"TRUE", true},
		{"false", false}, {"no", false}, {"off", false}, {"0", false}, {"FALSE", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			client, err := oidc.NewClientConfigFromDirectives("app", []string{"redirect_uris https://app.example.test/callback", "require_pkce " + tc.value, "skip_consent " + tc.value})
			if err != nil || client.RequirePKCE != tc.want || client.SkipConsent != tc.want {
				t.Fatal("directive did not follow repository boolean syntax")
			}
		})
	}
}
