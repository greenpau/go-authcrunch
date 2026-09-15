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
	"net/http"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

func TestCookieDeletionAttributes(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		config               *cookie.Config
		host, base, provider string
	}{
		{"defaults", &cookie.Config{Lifetime: 900, SameSite: "strict"}, "login.example.test", "/auth/", "PROVIDER_ID"},
		{"insecure", &cookie.Config{Insecure: true, Lifetime: 600}, "localhost", "/auth", "PROVIDER_ID"},
		{"secure prefix", &cookie.Config{CookieNamePrefix: "__Secure-PORTAL", Lifetime: 120}, "login.example.test", "/auth/", "__Secure-PROVIDER_ID"},
		{"host access and session", &cookie.Config{AccessTokenCookieName: "__Host-ACCESS", SessionIDCookieName: "__Host-SESSION"}, "login.example.test", "/", "PROVIDER_ID"},
		{"domain override", &cookie.Config{Insecure: true, Path: "/fallback", Lifetime: 900, SameSite: "strict", Domains: map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test", Path: "/tenant", Lifetime: 600, SameSite: "lax"}}}, "login.example.test:443", "/tenant/", "PROVIDER_ID"},
		{"stripped domain", &cookie.Config{Domains: map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test", StripDomainEnabled: true, Path: "/tenant"}}}, "login.example.test", "/tenant", "PROVIDER_ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := cookie.NewFactory(tc.config)
			if err != nil {
				t.Fatal(err)
			}
			pairs := map[string][2]string{
				"access":   {f.GetAccessTokenCookie(tc.host, "synthetic"), f.GetDeleteAccessTokenCookie(tc.host)},
				"session":  {f.GetSessionIDCookie(tc.host, "synthetic"), f.GetDeleteSessionIDCookie(tc.host)},
				"referer":  {f.GetRefererCookie(tc.base, "synthetic"), f.GetDeleteRefererCookie(tc.base)},
				"sandbox":  {f.GetSandboxIDCookie(tc.base, "synthetic"), f.GetDeleteSandboxIDCookie(tc.base)},
				"identity": {f.GetIdentityTokenCookie(tc.base, tc.provider, "synthetic"), f.GetDeleteIdentityTokenCookie(tc.provider, tc.base)},
				"refresh":  {f.GetRefreshTokenCookie(tc.base, "synthetic"), f.GetDeleteRefreshTokenCookie(tc.base)},
			}
			for role, pair := range pairs {
				t.Run(role, func(t *testing.T) {
					grant, err := http.ParseSetCookie(pair[0])
					if err != nil {
						t.Fatal(err)
					}
					deleted, err := http.ParseSetCookie(pair[1])
					if err != nil {
						t.Fatal(err)
					}
					if deleted.Name != grant.Name || deleted.Domain != grant.Domain || deleted.Path != grant.Path || deleted.Secure != grant.Secure || deleted.HttpOnly != grant.HttpOnly || deleted.SameSite != grant.SameSite {
						t.Fatal("deletion changed issuance name, scope or security attributes")
					}
					if deleted.MaxAge != -1 || !deleted.Expires.Equal(time.Unix(0, 0)) || deleted.Value == grant.Value {
						t.Fatal("deletion retained a live cookie")
					}
					if role == "identity" && deleted.Name != tc.provider {
						t.Fatal("portal overwrote provider name")
					}
					if deleted.Path == "" {
						t.Fatal("cookie omitted explicit path")
					}
				})
			}
		})
	}
}

func TestLegacyRefreshDeletionPrefixes(t *testing.T) {
	for _, name := range []string{"__Host-REFRESH", "__hOsT-REFRESH", "__Secure-REFRESH", "__sEcUrE-REFRESH"} {
		for _, insecure := range []bool{false, true} {
			f, err := cookie.NewFactory(&cookie.Config{RefreshTokenCookieName: name, Insecure: insecure})
			if err != nil {
				t.Fatal(err)
			}
			raw := f.GetDeleteRefreshTokenCookie("/")
			if name == "__Host-REFRESH" || name == "__hOsT-REFRESH" {
				if raw != "" || f.GetRefreshTokenCookie("/", "synthetic") != "" {
					t.Fatal("impossible legacy __Host- scope must not be emitted")
				}
				continue
			}
			c, err := http.ParseSetCookie(raw)
			if err != nil || !c.Secure || !c.HttpOnly || c.Path != "/api/refresh_token" || c.MaxAge != -1 {
				t.Fatal("legacy secure refresh cleanup is not browser-compatible")
			}
		}
	}
}

func TestCookieDynamicPrefixScope(t *testing.T) {
	f, err := cookie.NewFactory(&cookie.Config{RefererCookieName: "__Host-REFERER", SandboxIDCookieName: "__hOsT-SANDBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if f.ValidatePortalPath("/") != nil || f.ValidatePortalPath("/auth/") == nil {
		t.Fatal("dynamic portal mount validation failed")
	}
	for _, name := range []string{"PROVIDER_ID", "__Secure-PROVIDER_ID"} {
		if f.ValidateIdentityTokenCookieName(name) != nil {
			t.Fatal("compatible provider cookie rejected")
		}
	}
	if f.ValidateIdentityTokenCookieName("__hOsT-PROVIDER_ID") == nil {
		t.Fatal("whoami-scoped host prefix accepted")
	}
}
