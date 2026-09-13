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

package cookie_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

func TestCookiePrefixAfterDefaults(t *testing.T) {
	for _, initial := range []*cookie.Config{cookie.NewConfig(), {}, {CookieNamePrefix: "OLD"}} {
		initial.ApplyDefaults()
		for _, prefix := range []string{"PORTAL", "TENANT", "AUTHP"} {
			if err := initial.SetCookieNamePrefix(prefix); err != nil {
				t.Fatal(err)
			}
			values := map[string]string{
				"SESSION_ID": initial.SessionIDCookieName, "REDIRECT_URL": initial.RefererCookieName,
				"SANDBOX_ID": initial.SandboxIDCookieName, "ID_TOKEN": initial.IdentityTokenCookieName,
				"ACCESS_TOKEN": initial.AccessTokenCookieName, "REFRESH_TOKEN": initial.RefreshTokenCookieName,
				"OIDC_SESSION_ID": initial.OIDCSessionIDCookieName, "OIDC_REQUEST_ID": initial.OIDCRequestIDCookieName,
			}
			for suffix, name := range values {
				if name != prefix+"_"+suffix {
					t.Fatalf("prefix change omitted %s", suffix)
				}
			}
			data, err := json.Marshal(initial)
			if err != nil {
				t.Fatal(err)
			}
			var restored cookie.Config
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			factory, err := cookie.NewFactory(&restored)
			if err != nil || factory.OIDCSessionIDCookieName != prefix+"_OIDC_SESSION_ID" || factory.OIDCRequestIDCookieName != prefix+"_OIDC_REQUEST_ID" {
				t.Fatal("prefix was lost during reload/factory construction")
			}
		}
	}
	c := cookie.NewConfig()
	c.OIDCSessionIDCookieName, c.AccessTokenCookieName = "LOGIN_SESSION", "LOGIN_ACCESS"
	c.Domains = map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test", Path: "/login"}}
	c.Path, c.Lifetime, c.SameSite = "/login", 50, "strict"
	if err := c.SetCookieNamePrefix("PORTAL"); err != nil {
		t.Fatal(err)
	}
	if c.OIDCSessionIDCookieName != "LOGIN_SESSION" || c.AccessTokenCookieName != "LOGIN_ACCESS" || c.OIDCRequestIDCookieName != "PORTAL_OIDC_REQUEST_ID" || c.Path != "/login" || c.Lifetime != 50 || c.SameSite != "strict" || c.Domains["example.test"].Path != "/login" {
		t.Fatal("prefix change replaced explicit names or unrelated attributes")
	}
	if err := c.SetCookieNamePrefix(""); err != nil || c.OIDCRequestIDCookieName != "AUTHP_OIDC_REQUEST_ID" {
		t.Fatal("empty typed prefix did not restore defaults")
	}
}

func TestCookiePrefixFailureIsAtomic(t *testing.T) {
	for _, prefix := range []string{"bad prefix", "bad;prefix", "bad\r\nprefix", "TENANT"} {
		c := cookie.NewConfig()
		c.OIDCSessionIDCookieName = "TENANT_ACCESS_TOKEN"
		before := c.Clone()
		if err := c.SetCookieNamePrefix(prefix); err == nil || !reflect.DeepEqual(c, before) {
			t.Fatal("invalid prefix or resulting collision mutated configuration")
		}
	}
	var c *cookie.Config
	if c.SetCookieNamePrefix("TEST") == nil || c.Validate() == nil || c.Clone() != nil {
		t.Fatal("nil config handling changed")
	}
}

func TestCookieConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*cookie.Config)
	}{
		{"invalid name", func(c *cookie.Config) { c.OIDCRequestIDCookieName = "invalid name" }},
		{"invalid prefix", func(c *cookie.Config) { c.CookieNamePrefix = "invalid prefix" }},
		{"collision", func(c *cookie.Config) { c.OIDCRequestIDCookieName = c.RefreshTokenCookieName }},
		{"path injection", func(c *cookie.Config) { c.Path = "/; Secure" }},
		{"nil domain", func(c *cookie.Config) { c.Domains = map[string]*cookie.DomainConfig{"example.test": nil} }},
		{"invalid domain", func(c *cookie.Config) { c.Domains = map[string]*cookie.DomainConfig{"bad;domain": {}} }},
		{"empty domain", func(c *cookie.Config) { c.Domains = map[string]*cookie.DomainConfig{"": {}} }},
		{"duplicate normalized domain", func(c *cookie.Config) {
			c.Domains = map[string]*cookie.DomainConfig{"example.test": {}, ".example.test": {}}
		}},
		{"domain attributes", func(c *cookie.Config) {
			c.Domains = map[string]*cookie.DomainConfig{"example.test": {Domain: "bad;domain"}}
		}},
		{"domain same site", func(c *cookie.Config) { c.Domains = map[string]*cookie.DomainConfig{"example.test": {SameSite: "bad"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cookie.NewConfig()
			tc.change(c)
			if c.Validate() == nil {
				t.Fatal("invalid cookie configuration accepted")
			}
			if f, err := cookie.NewFactory(c); err == nil || f != nil {
				t.Fatal("factory accepted invalid configuration")
			}
		})
	}
}

func TestCookieConfigCloneAndDomainAttributes(t *testing.T) {
	c := cookie.NewConfig()
	c.Domains = map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test", StripDomainEnabled: true, SameSite: "lax"}, "other.test": nil}
	copy := c.Clone()
	copy.Domains["example.test"].Path = "/changed"
	delete(copy.Domains, "other.test")
	if c.Domains["example.test"].Path != "" || len(c.Domains) != 2 || c.Domains["other.test"] != nil {
		t.Fatal("clone shared domain settings")
	}
	f, err := cookie.NewFactory(copy)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"example.test", "auth.example.test"} {
		result, err := http.ParseSetCookie(f.GetAccessTokenCookie(host, "synthetic"))
		if err != nil || result.Domain != "" || result.SameSite != http.SameSiteLaxMode || result.Path != "/changed" {
			t.Fatal("domain policy did not emit a host-only cookie")
		}
		if strings.Contains(f.GetDeleteAccessTokenCookie(host), "Domain=") {
			t.Fatal("cookie deletion changed domain scope")
		}
	}
	if copy.Domains["example.test"].Domain != "example.test" {
		t.Fatal("issuing a cookie mutated domain selection")
	}
	// Older typed configurations may carry an unmatched map key. Preserve the
	// factory's fallback attributes instead of dereferencing a missing entry.
	f, err = cookie.NewFactory(&cookie.Config{Domains: map[string]*cookie.DomainConfig{
		"example.test": {Domain: "other.test", StripDomainEnabled: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := http.ParseSetCookie(f.GetAccessTokenCookie("other.test", "synthetic"))
	if err != nil || result.Domain != "" || result.Name != "AUTHP_ACCESS_TOKEN" {
		t.Fatal("unmatched domain entry lost fallback cookie attributes")
	}
}
