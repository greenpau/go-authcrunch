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

package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

func TestOAuthAuthorizationConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*OAuthAuthorizationConfig)
	}{
		{"provider", func(c *OAuthAuthorizationConfig) { c.IdentityProvider = "" }},
		{"http origin", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "http://app.test" }},
		{"origin credentials", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "https://user:secret@app.test" }},
		{"origin path", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "https://app.test/private" }},
		{"origin query", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "https://app.test?secret" }},
		{"origin fragment", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "https://app.test#secret" }},
		{"origin slashes", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = `https://app.test\evil` }},
		{"origin host", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "https://:123" }},
		{"origin port", func(c *OAuthAuthorizationConfig) { c.PublicOrigin = "https://app.test:invalid" }},
		{"base relative", func(c *OAuthAuthorizationConfig) { c.BasePath = "relative" }},
		{"base root", func(c *OAuthAuthorizationConfig) { c.BasePath = "/" }},
		{"base escaped", func(c *OAuthAuthorizationConfig) { c.BasePath = "/a/%2e%2e/b" }},
		{"base dots", func(c *OAuthAuthorizationConfig) { c.BasePath = "/a/../b" }},
		{"base double slash", func(c *OAuthAuthorizationConfig) { c.BasePath = "//evil" }},
		{"base query", func(c *OAuthAuthorizationConfig) { c.BasePath = "/a?b" }},
		{"cookie invalid", func(c *OAuthAuthorizationConfig) { c.SessionCookieName = "invalid name" }},
		{"cookie collision", func(c *OAuthAuthorizationConfig) { c.SessionCookieName = "same"; c.LoginCookieName = "same" }},
		{"lifetime", func(c *OAuthAuthorizationConfig) { c.SessionLifetime = 86401 }},
		{"negative lifetime", func(c *OAuthAuthorizationConfig) { c.SessionLifetime = -1 }},
		{"capacity", func(c *OAuthAuthorizationConfig) { c.MaxSessions = -1 }},
		{"pending capacity", func(c *OAuthAuthorizationConfig) { c.MaxPendingLogins = 65537 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &OAuthAuthorizationConfig{IdentityProvider: "provider"}
			tc.change(c)
			if c.Validate("policy") == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	c := &OAuthAuthorizationConfig{IdentityProvider: "provider"}
	if c.Validate("unsafe/name") == nil {
		t.Fatal("unsafe policy name accepted")
	}
	p := &PolicyConfig{Name: "policy", AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}
	if err := p.ConfigureOAuth(c); err != nil {
		t.Fatal(err)
	}
	c.IdentityProvider = "changed"
	if p.OAuth.IdentityProvider != "provider" {
		t.Fatal("config not snapshotted")
	}
	before := p.OAuth
	if p.ConfigureOAuth(&OAuthAuthorizationConfig{}) == nil || p.OAuth != before {
		t.Fatal("failed application mutated config")
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.AllowedTokenSources = []string{"header"}
	if p.Validate() == nil {
		t.Fatal("incompatible config accepted after validation")
	}
	p.AllowedTokenSources = nil
	p.ValidateBearerHeader = true
	if p.Validate() == nil {
		t.Fatal("JWT bearer validation accepted")
	}
	p.ValidateBearerHeader = false
	p.CryptoKeyStoreConfig = &kms.CryptoKeyStoreConfig{TokenName: "access_token"}
	if p.Validate() == nil {
		t.Fatal("typed JWT key configuration accepted")
	}
	p.CryptoKeyStoreConfig = &kms.CryptoKeyStoreConfig{AutoGenerateTag: "default", AutoGenerateAlgo: "ES512"}
	if err := p.Validate(); err != nil {
		t.Fatalf("derived key-store defaults rejected on repeated validation: %v", err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var restored PolicyConfig
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("derived key-store defaults rejected after JSON restoration: %v", err)
	}
	if err := p.ConfigureOAuth(nil); err != nil || p.OAuth != nil {
		t.Fatal("disable failed")
	}
}

func TestOAuthAuthorizationReturnURI(t *testing.T) {
	for _, tc := range []struct {
		target string
		valid  bool
	}{
		{"/private?q=a%2Bb", true}, {"/report%20name", true}, {"//evil.test/x", false}, {"/%2f%2fevil.test", false}, {"/%5cevil.test", false}, {"/\\evil.test", false}, {"https://evil.test/x", false}, {"/a/..//evil", true},
	} {
		t.Run(tc.target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			got, ok := oauthReturnURI(r)
			if ok != tc.valid {
				t.Fatalf("valid=%v want %v", ok, tc.valid)
			}
			if ok && got != tc.target {
				t.Fatal("return URI changed")
			}
		})
	}
}
