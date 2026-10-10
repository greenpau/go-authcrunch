// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cookie_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

func TestSAMLBrowserBindingCookie(t *testing.T) {
	c := cookie.NewConfig()
	c.SAMLSessionIDCookieName = "SAML_BROWSER"
	c.Insecure = true
	c.Domains = map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test"}}
	f, err := cookie.NewFactory(c)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := http.ParseSetCookie(f.GetSAMLSessionIDCookie("binding"))
	if err != nil {
		t.Fatal(err)
	}
	if issued.Name != "SAML_BROWSER" || issued.Domain != "" || issued.Path != "/" || issued.MaxAge != 300 || !issued.Secure || !issued.HttpOnly || issued.SameSite != http.SameSiteNoneMode {
		t.Fatalf("unsafe SAML binding cookie: %#v", issued)
	}
	deleted, err := http.ParseSetCookie(f.GetDeleteSAMLSessionIDCookie())
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Domain != issued.Domain || deleted.Path != issued.Path || !deleted.Secure || !deleted.HttpOnly || deleted.SameSite != issued.SameSite || deleted.MaxAge >= 0 {
		t.Fatal("SAML binding deletion changed cookie scope")
	}
	if _, err := cookie.NewFactory(&cookie.Config{SAMLSessionIDCookieName: cookie.DefaultCookieNamePrefix + "_" + cookie.DefaultAccessTokenCookieName}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("SAML binding name collision accepted")
	}
	host, err := cookie.NewFactory(&cookie.Config{SAMLSessionIDCookieName: "__Host-SAML"})
	if err != nil || !strings.HasPrefix(host.GetSAMLSessionIDCookie("binding"), "__Host-SAML=") {
		t.Fatal("optional __Host- SAML binding name rejected")
	}
}

func TestSAMLTransactionCookies(t *testing.T) {
	f, err := cookie.NewFactory(&cookie.Config{SAMLSessionIDCookieName: "__Host-SAML"})
	if err != nil {
		t.Fatal(err)
	}
	first := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if f.ValidateIdentityTokenCookieName(f.SAMLSessionIDCookieName+"_"+first) == nil || f.ValidateProviderLoginCookieName(f.SAMLSessionIDCookieName+"_"+first, "/") == nil {
		t.Fatal("provider cookie may overwrite transaction proof")
	}
	other := make([]byte, 32)
	other[0] = 1
	second := base64.RawURLEncoding.EncodeToString(other)
	a, err := http.ParseSetCookie(f.GetSAMLSessionIDCookieForState("first-proof", first))
	if err != nil {
		t.Fatal(err)
	}
	b, err := http.ParseSetCookie(f.GetSAMLSessionIDCookieForState("second-proof", second))
	if err != nil {
		t.Fatal(err)
	}
	if a.Name == b.Name || a.Name != f.SAMLSessionIDCookieNameForState(first) {
		t.Fatal("independent transactions share a cookie")
	}
	for _, issued := range []*http.Cookie{a, b} {
		if issued.Path != "/" || issued.Domain != "" || !issued.Secure || !issued.HttpOnly || issued.MaxAge != 300 || issued.SameSite != http.SameSiteNoneMode {
			t.Fatal("transaction proof lost its browser security attributes")
		}
	}
	deleted, err := http.ParseSetCookie(f.GetDeleteSAMLSessionIDCookieForState(first))
	if err != nil || deleted.Name != a.Name || deleted.Name == b.Name || deleted.MaxAge >= 0 || deleted.Path != a.Path || deleted.Domain != a.Domain {
		t.Fatal("completion deletes another transaction or changes cookie scope")
	}
	for _, invalid := range []string{"", "https://app.example/", first + "=", first[:42], strings.Repeat("a", 4096)} {
		if f.SAMLSessionIDCookieNameForState(invalid) != "" || f.GetSAMLSessionIDCookieForState("proof", invalid) != "" || f.GetDeleteSAMLSessionIDCookieForState(invalid) != "" {
			t.Fatal("invalid state selected a browser proof cookie")
		}
	}
	if _, err := cookie.NewFactory(&cookie.Config{SAMLSessionIDCookieName: "SAML", AccessTokenCookieName: "SAML_" + first}); err == nil {
		t.Fatal("access cookie may overwrite SAML proof")
	}
}
