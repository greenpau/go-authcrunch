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

package oidc

import (
	"crypto"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewProvider(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*Config, *Options)
		wantError string
	}{
		{name: "defaults"},
		{name: "disabled", change: func(c *Config, _ *Options) { c.Enabled = false }, wantError: "enabled configuration"},
		{name: "invalid issuer", change: func(c *Config, _ *Options) { c.Issuer = "http://auth.test" }, wantError: "canonical HTTPS"},
		{name: "invalid session cookie", change: func(_ *Config, o *Options) { o.SessionCookieName = "invalid name" }, wantError: "invalid oidc cookie name"},
		{name: "invalid request cookie", change: func(_ *Config, o *Options) { o.RequestCookieName = "invalid;name" }, wantError: "invalid oidc cookie name"},
		{name: "cookie collision", change: func(_ *Config, o *Options) { o.SessionCookieName = "REQUEST"; o.RequestCookieName = "REQUEST" }, wantError: "distinct names"},
		{name: "host cookie scoped path", change: func(_ *Config, o *Options) { o.SessionCookieName = "__Host-session" }, wantError: "root issuer path"},
		{name: "custom login", change: func(_ *Config, o *Options) { o.LoginURL = "https://auth.example.test/auth/sign-in?fresh=true" }},
		{name: "external login", change: func(_ *Config, o *Options) { o.LoginURL = "https://other.test/auth/login" }, wantError: "within the issuer"},
		{name: "login outside mount", change: func(_ *Config, o *Options) { o.LoginURL = "https://auth.example.test/other/login" }, wantError: "within the issuer"},
		{name: "login in similar mount", change: func(_ *Config, o *Options) { o.LoginURL = "https://auth.example.test/authentication/login" }, wantError: "within the issuer"},
		{name: "login traversal", change: func(_ *Config, o *Options) { o.LoginURL = "https://auth.example.test/auth/../login" }, wantError: "within the issuer"},
		{name: "login fragment", change: func(_ *Config, o *Options) { o.LoginURL = "https://auth.example.test/auth/login#form" }, wantError: "within the issuer"},
		{name: "login credentials", change: func(_ *Config, o *Options) { o.LoginURL = "https://user@auth.example.test/auth/login" }, wantError: "within the issuer"},
		{name: "invalid login", change: func(_ *Config, o *Options) { o.LoginURL = "https://%zz/auth/login" }, wantError: "within the issuer"},
		{name: "invalid login query", change: func(_ *Config, o *Options) { o.LoginURL = "https://auth.example.test/auth/login?q=%zz" }, wantError: "login URL query"},
		{name: "missing signing key", change: func(c *Config, _ *Options) { c.SigningKeyFiles = []string{"missing.pem"} }, wantError: "cannot open oidc"},
		{name: "invalid excluded key", change: func(_ *Config, o *Options) { o.ExcludedSigningKeys = []crypto.PublicKey{&rsa.PublicKey{}} }, wantError: "invalid excluded RSA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := oidcTestConfig()
			options := Options{}
			if tc.change != nil {
				tc.change(c, &options)
			}
			p, err := NewProvider(c, &unitIdentityVerifier{enabled: true}, options)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error=%v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			if p.sessionCookie != "AUTHP_OIDC_SESSION_ID" || p.requestCookie != "AUTHP_OIDC_REQUEST_ID" {
				t.Fatal("default cookie naming changed")
			}
			if options.LoginURL != "" && p.loginURL != options.LoginURL {
				t.Fatal("custom login URL ignored")
			}
			if c.SessionLifetimeSeconds != 0 || c.Clients[0].ClientName != "" {
				t.Fatal("constructor mutated caller configuration")
			}
			c.Realms[0] = "changed"
			c.Clients[0].RedirectURIs[0] = "https://changed.test/"
			if !p.SupportsRealm("local") || p.SupportsRealm("changed") || p.clients["client"].RedirectURIs[0] != "https://client.example.test/callback" {
				t.Fatal("provider retained mutable caller configuration")
			}
		})
	}
	if _, err := NewProvider(nil, &unitIdentityVerifier{}, Options{}); err == nil {
		t.Fatal("nil configuration accepted")
	}
	if _, err := NewProvider(oidcTestConfig(), nil, Options{}); err == nil {
		t.Fatal("missing verifier accepted")
	}
	var client *ClientConfig
	if client.Validate() == nil {
		t.Fatal("nil client accepted")
	}
}

func TestProviderPublicHTTPContract(t *testing.T) {
	f := newProviderFixture(t)
	var p OpenIDProvider = f.provider
	outside := httptest.NewRequest("GET", oidcTestOrigin+"/elsewhere", nil)
	response := httptest.NewRecorder()
	if p.HandleHTTP(response, outside) || response.Body.Len() != 0 || len(response.Header()) != 0 {
		t.Fatal("unmatched request was modified")
	}
	p.ServeHTTP(response, outside)
	if response.Code != http.StatusNotFound {
		t.Fatal("http.Handler did not reject an unmatched route")
	}
	for _, origin := range []string{oidcTestOrigin, "https://other.test"} {
		request := httptest.NewRequest("POST", oidcTestOrigin+"/auth/login", nil)
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		if accepted := p.ValidateLoginRequest(response, request); accepted != (origin == oidcTestOrigin) {
			t.Fatal("incorrect login origin validation")
		}
		if origin != oidcTestOrigin && (response.Code != 403 || response.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("login rejection lost protocol protections")
		}
	}
	metadata := p.Discovery()
	metadata["issuer"] = "https://other.test"
	metadata["scopes_supported"].([]string)[0] = "changed"
	if p.Discovery()["issuer"] != f.config.Issuer || p.Discovery()["scopes_supported"].([]string)[0] != "openid" {
		t.Fatal("discovery exposes mutable provider state")
	}
	keys := p.JWKS()["keys"].([]map[string]string)
	keys[0]["n"] = "changed"
	if p.JWKS()["keys"].([]map[string]string)[0]["n"] == "changed" {
		t.Fatal("JWKS exposes mutable provider state")
	}
	p.Close()
	p.Close()
	request := httptest.NewRequest("GET", f.config.Issuer+"/.well-known/openid-configuration", nil)
	response = httptest.NewRecorder()
	p.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("closed provider continued serving requests")
	}
}
