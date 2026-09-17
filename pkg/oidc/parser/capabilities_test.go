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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

func TestOIDCCapabilityDirectives(t *testing.T) {
	for _, extra := range [][]string{{"refresh lifetime -1"}, {"max refresh tokens -1"}, {"max refresh tokens 1000001"}, {"refresh lifetime 86401"}, {"acr x"}, {"acr x pwd", "acr x otp"}, {"acr x invented"}, {"acr x pwd pwd"}, {"refresh lifetime 10", "refresh lifetime 20"}, {`acr "" pwd`}} {
		statements := append(providerStatements(), extra...)
		if cfg, err := oidcparser.NewOIDCProviderConfigFromDirectives(statements, providerApplications()); err == nil || cfg != nil {
			t.Fatalf("accepted invalid capability directives %q", extra)
		}
	}
	for _, extra := range []string{"request_object_key x a", "request_object_key x a b c", "request_object_key x AA AQAB", "request_object_signing_alg HS256", "request_object_signing_alg RS256"} {
		cfg, err := oidcparser.NewOIDCClientConfigFromDirectives("web", []string{"redirect_uri https://rp.test/callback", extra})
		if err == nil || cfg != nil {
			t.Fatal("accepted invalid request verification registration")
		}
	}
	cfg, err := oidcparser.NewOIDCProviderConfigFromDirectives(append(providerStatements(), "acr urn:example:password pwd", "refresh lifetime 600", "max refresh tokens 42"), providerApplications())
	if err != nil || len(cfg.AuthenticationContexts) != 1 || cfg.RefreshLifetimeSeconds != 600 || cfg.MaxRefreshTokens != 42 {
		t.Fatal("capability directives not applied")
	}
}
func ExampleNewOIDCProviderConfigFromDirectives_authenticationContext() {
	client := &oidc.ClientConfig{ClientID: "web", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://rp.example.test/callback"}, Scopes: []string{"openid", "profile", "address", "phone", "offline_access"}, RequirePKCE: true}
	cfg, err := oidcparser.NewOIDCProviderConfigFromDirectives([]string{"issuer https://auth.example.test", "realms local", "signing key files dedicated.pem", "applications web", "acr urn:example:password pwd", "refresh lifetime 600", "max refresh tokens 200"}, map[string]*oidc.ClientConfig{"web": client})
	fmt.Println(err, cfg.AuthenticationContexts[0].Value, cfg.RefreshLifetimeSeconds, cfg.MaxRefreshTokens, cfg.Clients[0].RequirePKCE)
	// Output: <nil> urn:example:password 600 200 true
}

func TestOIDCRequestKeyRegistrationPersistence(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyLine := "request_object_key rp-key " + base64.RawURLEncoding.EncodeToString(key.N.Bytes()) + " AQAB"
	body := []string{"redirect_uri https://rp.example.test/callback", keyLine, "request_object_signing_alg RS256"}
	client, err := oidcparser.NewOIDCClientConfigFromDirectives("web", body)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := oidc.NewOAuthApplicationConfig("web", client)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	var restored oidc.OAuthApplicationConfig
	if json.Unmarshal(encoded, &restored) != nil {
		t.Fatal("restore registration")
	}
	parsed, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", body, &restored)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Client.ClientID != client.ClientID || parsed.Client.ClientSecret != client.ClientSecret || parsed.Client.RequestObjectSigningAlg != "RS256" || !parsed.Client.RequirePKCE {
		t.Fatal("persisted registration lost policy")
	}
	parsed.Client.RequestObjectKeys[0].KeyID = "changed"
	if restored.Client.RequestObjectKeys[0].KeyID != "rp-key" || client.RequestObjectKeys[0].KeyID != "rp-key" {
		t.Fatal("client key snapshots alias caller")
	}
	changed, err := oidcparser.NewOAuthApplicationConfigFromDirectives("oauth application web", []string{"redirect_uri https://rp.example.test/new"}, &restored)
	if err != nil || len(changed.Client.RequestObjectKeys) != 0 || changed.Client.RequestObjectSigningAlg != "" {
		t.Fatal("persisted request-signing policy inherited implicitly")
	}
	for _, extra := range [][]string{{keyLine}, {"request_object_signing_alg none"}} {
		if c, err := oidcparser.NewOIDCClientConfigFromDirectives("web", append(body, extra...)); err == nil || c != nil {
			t.Fatal("duplicate request key or algorithm accepted")
		}
	}
}
