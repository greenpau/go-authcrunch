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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func oidcTestConfig() *Config {
	return &Config{Enabled: true, Issuer: "https://auth.example.test/auth", Realms: []string{"local"}, SigningKeyFiles: []string{"../../testdata/rskeys/test_2_pri.pem"}, Clients: []*ClientConfig{{ClientID: "client", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.example.test/callback"}}}}
}

func TestOIDCConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		invalid bool
	}{
		{"defaults", func(*Config) {}, false},
		{"disabled", func(c *Config) { c.Enabled = false; c.Issuer = "" }, false},
		{"standalone API mount", func(c *Config) { c.Issuer += "/api/tenant" }, false},
		{"missing hostname", func(c *Config) { c.Issuer = "https://:443/auth" }, true},
		{"http issuer", func(c *Config) { c.Issuer = "http://auth.example.test" }, true},
		{"issuer userinfo", func(c *Config) { c.Issuer = "https://user@auth.example.test" }, true},
		{"issuer query", func(c *Config) { c.Issuer += "?a=b" }, true},
		{"issuer empty query", func(c *Config) { c.Issuer += "?" }, true},
		{"issuer fragment", func(c *Config) { c.Issuer += "#x" }, true},
		{"issuer empty fragment", func(c *Config) { c.Issuer += "#" }, true},
		{"issuer trailing slash", func(c *Config) { c.Issuer += "/" }, true},
		{"issuer encoded path", func(c *Config) { c.Issuer += "/%61" }, true},
		{"issuer traversal", func(c *Config) { c.Issuer += "/../tenant" }, true},
		{"root issuer", func(c *Config) { c.Issuer = "https://auth.example.test" }, false},
		{"nested issuer", func(c *Config) { c.Issuer += "/tenant" }, false},
		{"missing realms", func(c *Config) { c.Realms = nil }, true},
		{"duplicate realms", func(c *Config) { c.Realms = []string{"local", "local"} }, true},
		{"missing keys", func(c *Config) { c.SigningKeyFiles = nil }, true},
		{"duplicate keys", func(c *Config) { c.SigningKeyFiles = []string{"key", "key"} }, true},
		{"nil client", func(c *Config) { c.Clients = []*ClientConfig{nil} }, true},
		{"missing clients", func(c *Config) { c.Clients = nil }, true},
		{"duplicate clients", func(c *Config) { c.Clients = append(c.Clients, c.Clients[0]) }, true},
		{"empty id", func(c *Config) { c.Clients[0].ClientID = "" }, true},
		{"short secret", func(c *Config) { c.Clients[0].ClientSecret = "short" }, true},
		{"post secret", func(c *Config) { c.Clients[0].TokenEndpointAuthMethod = "client_secret_post" }, false},
		{"unknown method", func(c *Config) { c.Clients[0].TokenEndpointAuthMethod = "client_secret_jwt" }, true},
		{"public secret", func(c *Config) { c.Clients[0].TokenEndpointAuthMethod = "none" }, true},
		{"public", func(c *Config) {
			c.Clients[0].TokenEndpointAuthMethod = "none"
			c.Clients[0].ClientSecret = ""
		}, false},
		{"missing redirects", func(c *Config) { c.Clients[0].RedirectURIs = nil }, true},
		{"relative redirect", func(c *Config) { c.Clients[0].RedirectURIs = []string{"//evil.test/cb"} }, true},
		{"redirect fragment", func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://client.test/cb#"} }, true},
		{"redirect credentials", func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://u:p@client.test/cb"} }, true},
		{"redirect HTTP", func(c *Config) { c.Clients[0].RedirectURIs = []string{"http://client.test/cb"} }, true},
		{"public loopback", func(c *Config) {
			c.Clients[0].TokenEndpointAuthMethod = "none"
			c.Clients[0].ClientSecret = ""
			c.Clients[0].RedirectURIs = []string{"http://127.0.0.1:12345/callback"}
		}, false},
		{"scope lacks openid", func(c *Config) { c.Clients[0].Scopes = []string{"profile"} }, true},
		{"unknown scope", func(c *Config) { c.Clients[0].Scopes = []string{"openid", "admin"} }, true},
		{"negative lifetime", func(c *Config) { c.TokenLifetimeSeconds = -1 }, true},
		{"large lifetime", func(c *Config) { c.SessionLifetimeSeconds = 86401 }, true},
		{"negative capacity", func(c *Config) { c.MaxPendingRequests = -1 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := oidcTestConfig()
			tc.mutate(c)
			err := c.Validate()
			if (err != nil) != tc.invalid {
				t.Fatalf("validation error = %v, invalid = %v", err, tc.invalid)
			}
			if err == nil && c.Enabled {
				if c.TokenLifetimeSeconds != 300 || c.MaxSessions != 10000 {
					t.Fatal("defaults missing")
				}
				if c.Clients[0].TokenEndpointAuthMethod == "none" && !c.Clients[0].RequirePKCE {
					t.Fatal("public PKCE not enforced")
				}
				b, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				var decoded Config
				if err := json.Unmarshal(b, &decoded); err != nil {
					t.Fatal(err)
				}
				if err := decoded.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	var empty *Config
	if err := empty.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCParameters(t *testing.T) {
	for _, tc := range []struct {
		name, query, body, contentType string
		queryAllowed, invalid          bool
	}{
		{"query", "client_id=c", "", "", true, false},
		{"form", "", "client_id=c", "application/x-www-form-urlencoded", false, false},
		{"duplicate query", "client_id=c&client_id=c", "", "", true, true},
		{"duplicate form", "", "client_id=c&client_id=c", "application/x-www-form-urlencoded", false, true},
		{"mixed duplicate", "client_id=c", "client_id=c", "application/x-www-form-urlencoded", true, true},
		{"malformed query", "client_id=%xx", "", "", true, true},
		{"malformed form", "", "client_id=%xx", "application/x-www-form-urlencoded", false, true},
		{"token query", "client_id=c", "", "", false, true},
		{"json", "", `{}`, "application/json", false, true},
		{"large form", "", "a=" + strings.Repeat("x", oidcMaxRequestBytes), "application/x-www-form-urlencoded", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := "GET"
			if tc.body != "" {
				method = "POST"
			}
			r := httptest.NewRequest(method, "https://auth.test/token?"+tc.query, strings.NewReader(tc.body))
			r.URL.ForceQuery = false
			r.Header.Set("Content-Type", tc.contentType)
			_, err := oidcParameters(httptest.NewRecorder(), r, tc.queryAllowed)
			if (err != nil) != tc.invalid {
				t.Fatalf("invalid = %v, want %v", err != nil, tc.invalid)
			}
		})
	}
}

func TestOIDCPKCE(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if !oidcVerifyPKCE(challenge, verifier) {
		t.Fatal("RFC 7636 vector failed")
	}
	for _, value := range []string{"", verifier + "!", strings.Repeat("a", 129), verifier[:42], strings.Repeat("a", 43)} {
		if oidcVerifyPKCE(challenge, value) {
			t.Fatal("invalid verifier accepted")
		}
	}
	if oidcVerifyPKCE("", verifier) {
		t.Fatal("unexpected verifier accepted")
	}
}

func TestOIDCClientAuthentication(t *testing.T) {
	c := oidcTestConfig()
	c.Clients[0].ClientID = "client:+ ü"
	c.Clients[0].ClientSecret = strings.Repeat("a", 32) + "+ :ü"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	o := &Provider{clients: map[string]*ClientConfig{c.Clients[0].ClientID: c.Clients[0]}}
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request, url.Values)
		valid  bool
	}{
		{"encoded basic", func(*http.Request, url.Values) {}, true},
		{"matching id", func(_ *http.Request, v url.Values) { v.Set("client_id", c.Clients[0].ClientID) }, true},
		{"mismatched id", func(_ *http.Request, v url.Values) { v.Set("client_id", "another-client") }, false},
		{"mixed secret", func(_ *http.Request, v url.Values) { v.Set("client_secret", c.Clients[0].ClientSecret) }, false},
		{"duplicate header", func(r *http.Request, _ url.Values) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }, false},
		{"wrong secret", func(r *http.Request, _ url.Values) { r.SetBasicAuth(url.QueryEscape(c.Clients[0].ClientID), "wrong") }, false},
		{"unknown client", func(r *http.Request, _ url.Values) {
			r.SetBasicAuth("unknown", url.QueryEscape(c.Clients[0].ClientSecret))
		}, false},
		{"bad escaping", func(r *http.Request, _ url.Values) { r.SetBasicAuth("%ZZ", "secret") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://auth.test", nil)
			r.SetBasicAuth(url.QueryEscape(c.Clients[0].ClientID), url.QueryEscape(c.Clients[0].ClientSecret))
			v := url.Values{}
			tc.mutate(r, v)
			if (o.authenticateClient(r, v) != nil) != tc.valid {
				t.Fatal("unexpected client authentication result")
			}
		})
	}
}
