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
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestOAuthApplicationRedirectStatements(t *testing.T) {
	previousCallbacks := []string{"https://app.example.test/removed", "https://app.example.test/callback"}
	persisted, err := oidc.NewOAuthApplicationConfig("web", &oidc.ClientConfig{
		ClientID: "protocol-id", TokenEndpointAuthMethod: "none", RedirectURIs: previousCallbacks,
	})
	if err != nil {
		t.Fatal(err)
	}
	constructors := map[string]func(*testing.T, []string) (*oidc.ClientConfig, error){
		"provisioning": func(t *testing.T, body []string) (*oidc.ClientConfig, error) {
			t.Helper()
			return oidcparser.NewOIDCClientConfigFromDirectives("web", body)
		},
		"adaptation": func(t *testing.T, body []string) (*oidc.ClientConfig, error) {
			t.Helper()
			app, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", body, nil)
			if err != nil {
				if app != nil {
					t.Fatal("failed adaptation returned a partial application")
				}
				return nil, err
			}
			return app.Client, nil
		},
		"reload": func(t *testing.T, body []string) (*oidc.ClientConfig, error) {
			t.Helper()
			app, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", body, persisted)
			if !slices.Equal(persisted.Client.RedirectURIs, previousCallbacks) {
				t.Fatal("adaptation changed persisted callbacks")
			}
			if err != nil {
				if app != nil {
					t.Fatal("failed reload returned a partial application")
				}
				return nil, err
			}
			return app.Client, nil
		},
	}
	callbacks := []string{"https://App.example.test:443/a%2Fb?next=%2F&x=+", "https://app.example.test/callback"}
	for name, parse := range constructors {
		t.Run(name, func(t *testing.T) {
			body := []string{"client_id protocol-id", "token_endpoint_auth_method none", cfgutil.EncodeArgs([]string{"redirect_uri", callbacks[0]}), "scopes openid", cfgutil.EncodeArgs([]string{"redirect_uri", callbacks[1]})}
			original := slices.Clone(body)
			client, err := parse(t, body)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(client.RedirectURIs, callbacks) || !slices.Equal(body, original) {
				t.Fatal("repeated callbacks changed order, exact URI bytes, or caller input")
			}
			data, err := json.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if fields["redirect_uris"] == nil || fields["redirect_uri"] != nil {
				t.Fatal("directive change renamed serialized redirect array")
			}
			var restored oidc.ClientConfig
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := restored.Validate(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(restored.RedirectURIs, callbacks) {
				t.Fatal("native JSON lost callback bytes or order")
			}
			client.RedirectURIs[0] = "changed"
			again, err := parse(t, body)
			if err != nil || !slices.Equal(again.RedirectURIs, callbacks) {
				t.Fatal("adaptations share callback storage")
			}
			const sensitive = "synthetic-secret-must-not-appear-in-errors"
			for _, tc := range []struct {
				name  string
				lines []string
				want  string
			}{
				{"missing callbacks", nil, "distinct redirect_uris"},
				{"plural removed", []string{"redirect_uris " + sensitive}, "unsupported oidc application directive"},
				{"mixed spellings", []string{"redirect_uri " + callbacks[0], "redirect_uris " + callbacks[1]}, "unsupported oidc application directive"},
				{"missing URI", []string{"redirect_uri"}, "invalid oidc application directive"},
				{"empty URI", []string{`redirect_uri ""`}, "empty oidc application directive"},
				{"two URIs", []string{"redirect_uri " + callbacks[0] + " " + sensitive}, "requires one value"},
				{"duplicate URI", []string{"redirect_uri " + callbacks[0], "scopes openid", "redirect_uri " + callbacks[0]}, "distinct redirect_uris"},
				{"invalid URI", []string{"redirect_uri " + sensitive}, "invalid oidc redirect_uri"},
				{"spaced field", []string{"redirect uri " + callbacks[0]}, "unsupported oidc application directive"},
				{"grouped keyword", []string{cfgutil.EncodeArgs([]string{"redirect_uri " + callbacks[0], sensitive})}, "unsupported oidc application directive"},
				{"empty second URI", []string{"redirect_uri " + callbacks[0], `redirect_uri ""`}, "empty oidc application directive"},
				{"invalid second URI", []string{"redirect_uri " + callbacks[0], "redirect_uri " + sensitive}, "invalid oidc redirect_uri"},
				{"second URI has extra value", []string{"redirect_uri " + callbacks[0], "redirect_uri " + callbacks[1] + " " + sensitive}, "requires one value"},
				{"second URI has newline", []string{"redirect_uri " + callbacks[0], "redirect_uri " + callbacks[1] + "\n" + sensitive}, "invalid oidc application directive"},
				{"URI has surrounding spaces", []string{cfgutil.EncodeArgs([]string{"redirect_uri", " " + callbacks[0] + " "})}, "distinct redirect_uris"},
				{"duplicate scalar between callbacks", []string{"redirect_uri " + callbacks[0], "skip_consent on", "redirect_uri " + callbacks[1], "skip_consent off"}, "duplicate oidc application directive"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					statements := append([]string{"client_id protocol-id", "token_endpoint_auth_method none"}, tc.lines...)
					before := slices.Clone(statements)
					got, err := parse(t, statements)
					if err == nil || got != nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatal("malformed callback statement was not rejected as expected")
					}
					if strings.Contains(err.Error(), sensitive) || !slices.Equal(statements, before) {
						t.Fatal("rejected callback exposed a value or mutated input")
					}
				})
			}
		})
	}
}
