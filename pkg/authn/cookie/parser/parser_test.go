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
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewCookieConfigFromDirectives(t *testing.T) {
	defaults, err := cookieparser.NewCookieConfigFromDirectives(nil)
	if err != nil || !reflect.DeepEqual(defaults, cookie.NewConfig()) || defaults.SAMLSessionIDCookieName != "AUTHP_SAML_SESSION_ID" {
		t.Fatal("empty directives lost portal defaults")
	}
	for _, input := range [][]string{
		{"cookie prefix PORTAL", "cookie oidc session id name AUTHP_OIDC_SESSION_ID"},
		{"cookie oidc session id name AUTHP_OIDC_SESSION_ID", "cookie prefix PORTAL"},
	} {
		config, err := cookieparser.NewCookieConfigFromDirectives(input)
		if err != nil {
			t.Fatal(err)
		}
		if config.OIDCSessionIDCookieName != "AUTHP_OIDC_SESSION_ID" || config.OIDCRequestIDCookieName != "PORTAL_OIDC_REQUEST_ID" || config.AccessTokenCookieName != "PORTAL_ACCESS_TOKEN" {
			t.Fatal("explicit names must win independently of prefix order")
		}
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		var reloaded cookie.Config
		if json.Unmarshal(data, &reloaded) != nil || reloaded.Validate() != nil || !reflect.DeepEqual(config, &reloaded) {
			t.Fatal("cookie config did not survive reload")
		}
	}
}

func TestSAMLCookieDirective(t *testing.T) {
	for _, tc := range []struct {
		name       string
		directives []string
		want       string
		invalid    bool
	}{
		{name: "default", want: "AUTHP_SAML_SESSION_ID"},
		{name: "prefix", directives: []string{"cookie prefix PORTAL"}, want: "PORTAL_SAML_SESSION_ID"},
		{name: "explicit", directives: []string{"cookie saml session id name SAML_BROWSER"}, want: "SAML_BROWSER"},
		{name: "collision", directives: []string{"cookie saml session id name AUTHP_ACCESS_TOKEN"}, invalid: true},
		{name: "duplicate", directives: []string{"cookie saml session id name ONE", "cookie saml session id name TWO"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cookieparser.NewCookieConfigFromDirectives(tc.directives)
			if tc.invalid {
				if err == nil || got != nil {
					t.Fatal("invalid SAML cookie directive returned a configuration")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.SAMLSessionIDCookieName != tc.want {
				t.Fatalf("got %q, want %q", got.SAMLSessionIDCookieName, tc.want)
			}
		})
	}
}

func TestCookieDirectiveNamesAndAttributes(t *testing.T) {
	input := []string{
		"cookie prefix PORTAL", "cookie session id name CUSTOM_SESSION", "cookie redirect url name CUSTOM_REDIRECT",
		"cookie sandbox id name CUSTOM_SANDBOX", "cookie id token name CUSTOM_IDENTITY", "cookie access token name CUSTOM_ACCESS",
		"cookie refresh token name CUSTOM_REFRESH", "cookie oidc session id name CUSTOM_LOGIN", "cookie oidc request id name CUSTOM_REQUEST",
		"cookie saml session id name CUSTOM_SAML",
		cfgutil.EncodeArgs([]string{"cookie", "path", "/login path"}), "cookie lifetime 120", "cookie same site strict",
		"cookie insecure disabled", "cookie strip domain enabled", "cookie guess domain disabled",
		"cookie domain .EXAMPLE.test", "cookie domain example.test path /tenant", "cookie domain example.test lifetime 90",
		"cookie domain example.test samesite none", "cookie domain example.test insecure enabled", "cookie domain example.test strip domain enabled",
		"cookie domain other.test", "cookie domain other.test insecure disabled", "cookie domain other.test strip domain disabled",
	}
	original := slices.Clone(input)
	for range 2 {
		c, err := cookieparser.NewCookieConfigFromDirectives(input)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"CUSTOM_SESSION", "CUSTOM_REDIRECT", "CUSTOM_SANDBOX", "CUSTOM_IDENTITY", "CUSTOM_ACCESS", "CUSTOM_REFRESH", "CUSTOM_LOGIN", "CUSTOM_REQUEST", "CUSTOM_SAML"}
		got := []string{c.SessionIDCookieName, c.RefererCookieName, c.SandboxIDCookieName, c.IdentityTokenCookieName, c.AccessTokenCookieName, c.RefreshTokenCookieName, c.OIDCSessionIDCookieName, c.OIDCRequestIDCookieName, c.SAMLSessionIDCookieName}
		if !slices.Equal(want, got) || c.Path != "/login path" || c.Lifetime != 120 || c.SameSite != "Strict" || c.Insecure || !c.StripDomainEnabled || c.GuessDomainEnabled {
			t.Fatal("cookie settings changed during parsing")
		}
		domain := c.Domains["example.test"]
		if domain.Domain != "example.test" || domain.Seq != 0 || domain.Path != "/tenant" || domain.Lifetime != 90 || domain.SameSite != "None" || !domain.Insecure || !domain.StripDomainEnabled || c.Domains["other.test"].Seq != 1 {
			t.Fatal("domain settings or order changed")
		}
		f, err := cookie.NewFactory(c)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := http.ParseSetCookie(f.GetAccessTokenCookie("auth.example.test", "synthetic"))
		if err != nil || issued.Domain != "" || issued.Name != "CUSTOM_ACCESS" || issued.Path != "/tenant" || issued.MaxAge != 90 || issued.SameSite != http.SameSiteNoneMode {
			t.Fatal("parsed domain policy not applied by factory")
		}
		c.OIDCSessionIDCookieName, domain.Path = "changed", "/changed"
	}
	if !slices.Equal(input, original) {
		t.Fatal("parser mutated input")
	}
	for _, state := range []string{"enabled", "disabled"} {
		for _, keyword := range []string{"insecure", "strip domain", "guess domain"} {
			c, err := cookieparser.NewCookieConfigFromDirectives([]string{"cookie " + keyword + " " + state})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{"insecure": c.Insecure, "strip domain": c.StripDomainEnabled, "guess domain": c.GuessDomainEnabled}[keyword]
			if got != (state == "enabled") {
				t.Fatal("cookie state was inverted")
			}
		}
	}
}

func TestCookieDirectiveRejections(t *testing.T) {
	for _, input := range [][]string{
		{""}, {"cookie"}, {"prefix PORTAL"}, {"cookie {"}, {"cookie unknown sensitive-value"},
		{"cookie prefix"}, {`cookie prefix ""`}, {"cookie prefix one two"}, {"cookie prefix bad;prefix"}, {"cookie prefix A", "cookie prefix B"},
		{"cookie oidc session id name"}, {"cookie oidc request id name one two"}, {`cookie oidc session id name "bad name"`},
		{"cookie oidc session id name same", "cookie oidc request id name same"}, {"cookie oidc session id name AUTHP_ACCESS_TOKEN"},
		{"cookie referer name one", "cookie redirect url name two"}, {"cookie identity token name one", "cookie id token name two"},
		{`cookie "oidc session id" name CUSTOM`}, {`cookie "same site" lax`}, {"cookie same_site lax"},
		{"cookie insecure true"}, {"cookie guess domain 0"}, {"cookie strip domain enabled", "cookie strip domain disabled"},
		{"cookie lifetime 1.5"}, {"cookie lifetime 99999999999999999999999"}, {"cookie lifetime 1", "cookie lifetime 2"},
		{"cookie same site bad"}, {"cookie same site lax", "cookie samesite strict"}, {"cookie path /;Secure"},
		{"cookie domain"}, {"cookie domain bad;domain"}, {"cookie domain .example.test", "cookie domain example.test"},
		{"cookie domain example.test guess domain enabled"}, {"cookie domain example.test path /a", "cookie domain example.test path /b"},
		{"cookie domain example.test bogus x"}, {"cookie domain example.test lifetime"}, {"cookie domain example.test insecure true"},
		{"cookie domain example.test same site lax", "cookie domain example.test samesite strict"},
		{"cookie prefix A\ncookie prefix B"}, {"cookie prefix A\r"}, {"cookie prefix \xff"}, {`cookie prefix "unterminated`},
		{`cookie path " "`},
	} {
		original := slices.Clone(input)
		got, err := cookieparser.NewCookieConfigFromDirectives(input)
		if got != nil || err == nil || strings.Contains(err.Error(), "sensitive-value") || !slices.Equal(input, original) {
			t.Fatalf("invalid directives accepted, disclosed, or mutated: %v", original)
		}
	}
}

func ExampleNewCookieConfigFromDirectives() {
	config, err := cookieparser.NewCookieConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"cookie", "prefix", "PORTAL"}),
		cfgutil.EncodeArgs([]string{"cookie", "oidc", "session", "id", "name", "LOGIN_SESSION"}),
		cfgutil.EncodeArgs([]string{"cookie", "saml", "session", "id", "name", "SAML_BROWSER"}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(config.AccessTokenCookieName, config.OIDCSessionIDCookieName, config.OIDCRequestIDCookieName, config.SAMLSessionIDCookieName)
	// Output: PORTAL_ACCESS_TOKEN LOGIN_SESSION PORTAL_OIDC_REQUEST_ID SAML_BROWSER
}

func TestCookieReservedPrefixValidation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		directives []string
		invalid    bool
	}{
		{"ordinary insecure", []string{"cookie prefix PORTAL", "cookie insecure enabled"}, false},
		{"secure prefix", []string{"cookie prefix __Secure-PORTAL"}, false},
		{"secure prefix insecure", []string{"cookie prefix __sEcUrE-PORTAL", "cookie insecure enabled"}, true},
		{"host access session", []string{"cookie access token name __Host-ACCESS", "cookie session id name __hOsT-SESSION"}, false},
		{"host access path", []string{"cookie access token name __Host-ACCESS", "cookie path /auth"}, true},
		{"host session domain", []string{"cookie session id name __Host-SESSION", "cookie domain example.test"}, true},
		{"host access domain path", []string{"cookie access token name __Host-ACCESS", "cookie domain example.test strip domain enabled", "cookie domain example.test path /auth"}, true},
		{"host stripped domain", []string{"cookie access token name __Host-ACCESS", "cookie domain example.test strip domain enabled"}, false},
		{"host guessed domain", []string{"cookie access token name __Host-ACCESS", "cookie guess domain enabled"}, true},
		{"host stripped guess", []string{"cookie access token name __Host-ACCESS", "cookie guess domain enabled", "cookie strip domain enabled"}, false},
		{"host provider fallback", []string{"cookie identity token name __Host-ID"}, true},
		{"feature-owned host names", []string{"cookie refresh token name __Host-REFRESH", "cookie oidc session id name __Host-OIDC"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := cookieparser.NewCookieConfigFromDirectives(tc.directives)
			if tc.invalid {
				if err == nil || c != nil {
					t.Fatal("invalid reserved-prefix configuration returned a snapshot")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var restored cookie.Config
			if json.Unmarshal(raw, &restored) != nil {
				t.Fatal("cookie JSON roundtrip failed")
			}
			if _, err := cookie.NewFactory(&restored); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Typed and JSON consumers must enforce the same validation as directives.
	for _, raw := range []string{
		`{"access_token_cookie_name":"__Host-ACCESS","path":"/auth"}`,
		`{"session_id_cookie_name":"__Secure-SESSION","insecure":true}`,
		`{"identity_token_cookie_name":"__Host-ID"}`,
	} {
		var c cookie.Config
		if json.Unmarshal([]byte(raw), &c) != nil {
			t.Fatal("malformed fixture")
		}
		if c.Validate() == nil {
			t.Fatal("typed configuration bypassed prefix validation")
		}
		if _, err := cookie.NewFactory(&c); err == nil {
			t.Fatal("factory bypassed prefix validation")
		}
	}
}
