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
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewOAuthApplicationConfigFromDirectives(t *testing.T) {
	const callback = "https://app.example.test/callback"
	secret := strings.Repeat("s", 32) + ` +/:,"quoted" secret`
	previous, err := oidc.NewOAuthApplicationConfig("my application", &oidc.ClientConfig{
		ClientID: "protocol-id", ClientSecret: secret, RedirectURIs: []string{callback}, Scopes: []string{"openid"}, SkipConsent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	header := cfgutil.EncodeArgs([]string{"oauth", "application", previous.Name})
	for _, tc := range []struct {
		name               string
		statements         []string
		persisted          *oidc.OAuthApplicationConfig
		id, secret, method string
		pkce               bool
	}{
		{"explicit", []string{"client_id protocol-id", cfgutil.EncodeArgs([]string{"client_secret", secret})}, nil, "protocol-id", secret, "client_secret_basic", true},
		{"restored", nil, previous, "protocol-id", secret, "client_secret_basic", true},
		{"same explicit ID", []string{"client_id protocol-id"}, previous, "protocol-id", secret, "client_secret_basic", true},
		{"secret rotation", []string{"client_secret " + strings.Repeat("r", 32)}, previous, "protocol-id", strings.Repeat("r", 32), "client_secret_basic", true},
		{"new ID and secret", []string{"client_id new-id", "client_secret " + strings.Repeat("r", 32)}, previous, "new-id", strings.Repeat("r", 32), "client_secret_basic", true},
		{"post and no PKCE", []string{"token_endpoint_auth_method client_secret_post", "require_pkce off"}, previous, "protocol-id", secret, "client_secret_post", false},
		{"public", []string{"client_id desktop", "token_endpoint_auth_method none"}, nil, "desktop", "", "none", true},
		{"change to public", []string{"token_endpoint_auth_method none"}, previous, "protocol-id", "", "none", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statements := append([]string{"redirect_uris " + callback}, tc.statements...)
			application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(header, statements, tc.persisted)
			if err != nil {
				t.Fatal(err)
			}
			client := application.Client
			if application.Name != previous.Name || client.ClientName != previous.Name || client.ClientID != tc.id || client.ClientSecret != tc.secret || client.TokenEndpointAuthMethod != tc.method || client.RequirePKCE != tc.pkce {
				t.Fatal("application identity, credentials, or settings differ")
			}
			if client.SkipConsent || len(client.Scopes) != 3 {
				t.Fatal("adaptation inherited old policy instead of applying current directives")
			}
		})
	}
}

func TestOAuthApplicationDirectiveRejections(t *testing.T) {
	const sentinel = "sensitive-value-that-must-not-be-echoed"
	previous, err := oidc.NewOAuthApplicationConfig("web", &oidc.ClientConfig{ClientID: "old-id", ClientSecret: sentinel, RedirectURIs: []string{"https://app.example.test/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, header string
		body         []string
		previous     *oidc.OAuthApplicationConfig
		want         string
	}{
		{"empty header", "", nil, nil, "header"},
		{"wrong kind", "oauth provider " + sentinel, nil, nil, "header"},
		{"wrong domain", "oidc application web", nil, nil, "header"},
		{"missing nickname", "oauth application", nil, nil, "header"},
		{"extra header argument", "oauth application web " + sentinel, nil, nil, "header"},
		{"opening brace", "oauth application web {", nil, nil, "header"},
		{"grouped keywords", `"oauth application" web`, nil, nil, "header"},
		{"multiline", "oauth application web\n" + sentinel, nil, nil, "header"},
		{"invalid quoting", `oauth application "` + sentinel, nil, nil, "header"},
		{"empty nickname", `oauth application ""`, nil, nil, "nickname"},
		{"nickname mismatch", "oauth application other", nil, previous, "does not match"},
		{"invalid persisted", "oauth application web", nil, &oidc.OAuthApplicationConfig{Name: "web"}, "persisted"},
		{"missing credentials", "oauth application web", nil, nil, "persisted client_id"},
		{"missing secret", "oauth application web", []string{"client_id web"}, nil, "persisted client_secret"},
		{"changed ID", "oauth application web", []string{"client_id new-id"}, previous, "persisted client_secret"},
		{"empty ID", "oauth application web", []string{`client_id ""`}, previous, "empty"},
		{"empty secret", "oauth application web", []string{`client_secret ""`}, previous, "empty"},
		{"duplicate credential", "oauth application web", []string{"client_secret " + sentinel, "client_secret " + sentinel}, previous, "duplicate"},
		{"unknown body field", "oauth application web", []string{sentinel + " true"}, previous, "unsupported"},
		{"invalid bool", "oauth application web", []string{"skip_consent " + sentinel}, previous, "boolean"},
		{"public secret", "oauth application web", []string{"client_id web", "token_endpoint_auth_method none", "client_secret " + sentinel}, nil, "cannot have a secret"},
		{"public no PKCE", "oauth application web", []string{"client_id web", "token_endpoint_auth_method none", "require_pkce off"}, nil, "require PKCE"},
		{"unsupported auth", "oauth application web", []string{"token_endpoint_auth_method " + sentinel}, previous, "unsupported"},
		{"missing current redirects", "oauth application web", []string{"scopes openid"}, previous, "redirect_uris"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := append([]string{"redirect_uris https://app.example.test/callback"}, tc.body...)
			if tc.name == "missing current redirects" {
				body = tc.body
			}
			result, err := oidcparser.NewOAuthApplicationConfigFromDirectives(tc.header, body, tc.previous)
			if result != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %s rejection; got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("error exposed a supplied value")
			}
		})
	}
}

func TestOAuthApplicationDirectivesConcurrentReload(t *testing.T) {
	client, err := oidcparser.NewOIDCClientConfigFromDirectives("web", []string{"redirect_uris https://app.example.test/callback"})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := oidc.NewOAuthApplicationConfig("web", client)
	if err != nil {
		t.Fatal(err)
	}
	original, err := oidc.NewOAuthApplicationConfig("web", client)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{"redirect_uris https://changed.example.test/callback", "scopes openid"}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 4 {
				result, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", statements, persisted)
				if err != nil {
					t.Error(err)
					return
				}
				if result.Client.ClientID != client.ClientID || result.Client.ClientSecret != client.ClientSecret {
					t.Error("reload changed credentials")
				}
				result.Client.Scopes[0] = "modified"
				result.Client.RedirectURIs[0] = "modified"
			}
		})
	}
	workers.Wait()
	if !reflect.DeepEqual(persisted, original) || statements[0] != "redirect_uris https://changed.example.test/callback" {
		t.Fatal("adaptation changed immutable inputs")
	}
}
