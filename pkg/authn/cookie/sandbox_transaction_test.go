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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

func TestSandboxTransactionCookies(t *testing.T) {
	id := strings.Repeat("a", 36)
	for _, tc := range []struct {
		name, base, prefix string
		insecure           bool
	}{
		{"root", "/", "__Host-FLOW", false}, {"nested", "/tenant/auth/", "DEST_SANDBOX_ID", false}, {"legacy insecure", "/auth/", "FLOW", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := cookie.NewFactory(&cookie.Config{SandboxIDCookieName: tc.prefix, Insecure: tc.insecure, Lifetime: 86400, Path: "/unrelated", Domains: map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test"}}})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := http.ParseSetCookie(f.GetSandboxIDCookieForSession(tc.base, "proof", id))
			if err != nil {
				t.Fatal(err)
			}
			path := strings.TrimSuffix(tc.base, "/")
			if path == "" {
				path = "/"
			}
			if issued.Name != tc.prefix+"_"+id || issued.Path != path || issued.Domain != "" || issued.MaxAge != 300 || issued.Secure == tc.insecure || !issued.HttpOnly || issued.SameSite != http.SameSiteLaxMode {
				t.Fatal("flow cookie attributes differ from contract")
			}
			deleted, err := http.ParseSetCookie(f.GetDeleteSandboxIDCookieForSession(tc.base, id))
			if err != nil || deleted.Name != issued.Name || deleted.Path != issued.Path || deleted.Domain != issued.Domain || deleted.Secure != issued.Secure || deleted.HttpOnly != issued.HttpOnly || deleted.SameSite != issued.SameSite || deleted.MaxAge >= 0 {
				t.Fatal("flow deletion changes proof scope")
			}
			if f.SandboxIDCookieNameForSession(strings.Repeat("b", 47)) == issued.Name {
				t.Fatal("flows share a proof name")
			}
			legacy, err := http.ParseSetCookie(f.GetSandboxIDCookie(tc.base, "legacy"))
			if err != nil || legacy.Name != tc.prefix || legacy.MaxAge != 86400 {
				t.Fatal("legacy factory contract changed")
			}
			for _, invalid := range []string{"", strings.Repeat("a", 35), strings.Repeat("a", 48), id[:35] + "-", id[:35] + "_", id + "/", id + "\r\n"} {
				if f.SandboxIDCookieNameForSession(invalid) != "" || f.GetSandboxIDCookieForSession(tc.base, "proof", invalid) != "" || f.GetDeleteSandboxIDCookieForSession(tc.base, invalid) != "" {
					t.Fatal("invalid selector generated proof cookie")
				}
			}
		})
	}
}

func TestSandboxTransactionNameReservations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *cookie.Config
	}{
		{"access", &cookie.Config{SandboxIDCookieName: "FLOW", AccessTokenCookieName: "FLOW_any"}},
		{"session", &cookie.Config{SandboxIDCookieName: "FLOW", SessionIDCookieName: "FLOW_any"}},
		{"SAML inside sandbox", &cookie.Config{SandboxIDCookieName: "FLOW", SAMLSessionIDCookieName: "FLOW_saml"}},
		{"sandbox inside SAML", &cookie.Config{SandboxIDCookieName: "SAML_flow", SAMLSessionIDCookieName: "SAML"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cookie.NewFactory(tc.config); err == nil {
				t.Fatal("reserved dynamic prefix overlap accepted")
			}
		})
	}
	f, err := cookie.NewFactory(&cookie.Config{SandboxIDCookieName: "FLOW"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"FLOW_any", "FLOW_" + strings.Repeat("a", 36)} {
		if f.ValidateProviderLoginCookieName(name, "/") == nil || f.ValidateIdentityTokenCookieName(name) == nil {
			t.Fatal("provider can overwrite a sandbox proof")
		}
	}
	if f.ValidateProviderLoginCookieName("OTHER_FLOW", "/") != nil || f.ValidateIdentityTokenCookieName("OTHER_FLOW") != nil {
		t.Fatal("unrelated provider name rejected")
	}
	if f.ValidatePortalPath("/nested/") != nil {
		t.Fatal("ordinary nested mount rejected")
	}
	host, err := cookie.NewFactory(&cookie.Config{SandboxIDCookieName: "__Host-FLOW"})
	if err != nil {
		t.Fatal(err)
	}
	if host.ValidatePortalPath("/") != nil || host.ValidatePortalPath("/nested/") == nil {
		t.Fatal("reserved host mount validation changed")
	}
}
