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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestOIDCLoopbackRedirectMatching(t *testing.T) {
	for _, tc := range []struct {
		name, registered, requested, method string
		allowed                             bool
	}{
		{"IPv4", "http://127.0.0.1:43111/callback?q=a%20b", "http://127.0.0.1:43112/callback?q=a%20b", "none", true},
		{"IPv6", "http://[::1]:43111/callback", "http://[::1]:43112/callback", "none", true},
		{"omitted port", "http://127.0.0.1/callback", "http://127.0.0.1:43112/callback", "none", true},
		{"default requested port", "http://[::1]:43111/callback", "http://[::1]/callback", "none", true},
		{"minimum port", "http://127.0.0.1/callback", "http://127.0.0.1:1/callback", "none", true},
		{"maximum port", "http://127.0.0.1/callback", "http://127.0.0.1:65535/callback", "none", true},
		{"exact confidential", "https://client.test:43111/callback", "https://client.test:43111/callback", "client_secret_basic", true},
		{"confidential port", "https://client.test:43111/callback", "https://client.test:43112/callback", "client_secret_basic", false},
		{"HTTPS public port", "https://127.0.0.1:43111/callback", "https://127.0.0.1:43112/callback", "none", false},
		{"HTTPS exact", "https://127.0.0.1:43111/callback", "https://127.0.0.1:43111/callback", "none", true},
		{"IPv4 to IPv6", "http://127.0.0.1:43111/callback", "http://[::1]:43112/callback", "none", false},
		{"scheme case", "http://127.0.0.1:43111/callback", "HTTP://127.0.0.1:43112/callback", "none", false},
		{"path escape", "http://127.0.0.1:43111/c%61llback", "http://127.0.0.1:43112/callback", "none", false},
		{"escape case", "http://127.0.0.1:43111/c%2fb", "http://127.0.0.1:43112/c%2Fb", "none", false},
		{"query order", "http://127.0.0.1:43111/callback?a=1&b=2", "http://127.0.0.1:43112/callback?b=2&a=1", "none", false},
		{"query escape", "http://127.0.0.1:43111/callback?q=a%20b", "http://127.0.0.1:43112/callback?q=a+b", "none", false},
		{"empty query", "http://127.0.0.1:43111/callback?", "http://127.0.0.1:43112/callback", "none", false},
		{"empty path", "http://127.0.0.1:43111", "http://127.0.0.1:43112/", "none", false},
		{"dot segment", "http://127.0.0.1:43111/callback", "http://127.0.0.1:43112/./callback", "none", false},
		{"path case", "http://127.0.0.1:43111/callback", "http://127.0.0.1:43112/Callback", "none", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &ClientConfig{ClientID: "native", TokenEndpointAuthMethod: tc.method, RedirectURIs: []string{tc.registered}}
			if tc.method != "none" {
				c.ClientSecret = strings.Repeat("s", 32)
			}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			if got := c.allowsRedirectURI(tc.requested); got != tc.allowed {
				t.Fatalf("redirect match=%t, want %t", got, tc.allowed)
			}
		})
	}
}

func TestOIDCLoopbackRedirectRejections(t *testing.T) {
	invalid := []string{
		"http://127.0.0.1:/callback", "http://127.0.0.1:0/callback", "http://127.0.0.1:65536/callback", "http://127.0.0.1:999999999999999999999999/callback",
		"http://[::1]:/callback", "http://[::1]:0/callback", "http://[::1]:65536/callback", "http://127.0.0.1:abc/callback", "http://127.0.0.1:+12/callback", "http://127.0.0.1:-1/callback",
		"http://127.0.0.1:123/callback#", "http://127.0.0.1:123/callback#fragment", "http://alice@127.0.0.1:123/callback", "http://127.0.0.1:123/callback?q=%XX", "http://127.0.0.1:123/callback?q=a;b",
		"http://localhost:123/callback", "http://127.0.0.2:123/callback", "http://127.0.0.1.evil.test:123/callback", "http://[::ffff:127.0.0.1]:123/callback", "http://[0:0:0:0:0:0:0:1]:123/callback", "http://[::1%25lo0]:123/callback", "http://[127.0.0.1]:123/callback", "http://127.1:123/callback", "http://2130706433:123/callback", "http://127.0.0.01:123/callback",
		"http://127.0.0.1:123/\\callback", "http://127.0.0.1:123/call\nback", "//127.0.0.1:123/callback", "com.example.app:/callback",
	}
	c := &ClientConfig{ClientID: "native", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1:43111/callback"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			candidate := *c
			candidate.RedirectURIs = []string{raw}
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid native callback registered")
			}
			if c.allowsRedirectURI(raw) {
				t.Fatal("invalid native callback accepted")
			}
		})
	}
	confidential := &ClientConfig{ClientID: "web", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"http://127.0.0.1:43111/callback"}}
	if confidential.Validate() == nil {
		t.Fatal("confidential HTTP loopback registration accepted")
	}
}

func TestOIDCLoopbackCodeBinding(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			cfg := oidcTestConfig()
			registered := "http://" + host + ":43111/callback?q=registered"
			actual := "http://" + host + ":43112/callback?q=registered"
			cfg.Clients = []*ClientConfig{{ClientID: "native", TokenEndpointAuthMethod: "none", RedirectURIs: []string{registered}, SkipConsent: true}}
			verifier := &unitIdentityVerifier{enabled: true}
			provider, err := NewProvider(cfg, verifier, Options{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			fixture := &providerFixture{provider: provider, config: cfg, verifier: verifier}
			cookie := responseCookie(t, fixture.login(t), provider.sessionCookie)
			proof := strings.Repeat("v", 43)
			sum := sha256.Sum256([]byte(proof))
			params := url.Values{"client_id": {"native"}, "redirect_uri": {actual}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
			code := oidcUnitCode(t, oidcUnitRequest(t, fixture, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, cookie))
			form := url.Values{"client_id": {"native"}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {registered}, "code_verifier": {proof}}
			for _, wrong := range []string{registered, "http://" + host + ":43113/callback?q=registered", "http://" + host + ":43112/callback?q=changed"} {
				form.Set("redirect_uri", wrong)
				denied := oidcUnitRequest(t, fixture, http.MethodPost, "/oidc/token", form, nil)
				var body map[string]string
				if denied.Code != http.StatusBadRequest || json.Unmarshal(denied.Body.Bytes(), &body) != nil || body["error"] != "invalid_grant" {
					t.Fatal("code redeemed with a different actual URI")
				}
			}
			form.Set("redirect_uri", actual)
			if result := oidcUnitRequest(t, fixture, http.MethodPost, "/oidc/token", form, nil); result.Code != http.StatusOK {
				t.Fatal("actual callback could not redeem code")
			}
			params.Del("code_challenge")
			params.Del("code_challenge_method")
			denied := oidcUnitRequest(t, fixture, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, cookie)
			target, err := url.Parse(denied.Header().Get("Location"))
			if err != nil || target.Query().Get("error") != "invalid_request" || target.Query().Get("code") != "" {
				t.Fatal("native callback bypassed PKCE")
			}
		})
	}
}

func FuzzOIDCLoopbackRedirect(f *testing.F) {
	for _, seed := range []string{"http://127.0.0.1:43112/callback?q=a%20b", "http://[::1]:43112/callback?q=a%20b", "http://localhost:43112/callback?q=a%20b", "http://127.0.0.1:65536/callback?q=a%20b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, host := range []string{"127.0.0.1", "[::1]"} {
			registered := "http://" + host + ":43111/callback?q=a%20b"
			c := &ClientConfig{TokenEndpointAuthMethod: "none", RequirePKCE: true, RedirectURIs: []string{registered}}
			if !c.allowsRedirectURI(raw) {
				continue
			}
			// Independently require exact prefix/suffix and a decimal usable port.
			prefix := "http://" + host
			rest, ok := strings.CutPrefix(raw, prefix)
			if !ok {
				t.Fatal("allowed a different host/scheme")
			}
			port, suffix, hasPath := strings.Cut(rest, "/")
			if !hasPath || suffix != "callback?q=a%20b" {
				t.Fatal("allowed a different raw path/query")
			}
			if port == "" {
				continue
			}
			digits, ok := strings.CutPrefix(port, ":")
			if !ok || digits == "" {
				t.Fatal("malformed port accepted")
			}
			value := uint64(0)
			for _, r := range digits {
				if r < '0' || r > '9' {
					t.Fatal("nonnumeric port accepted")
				}
				value = value*10 + uint64(r-'0')
				if value > 65535 {
					t.Fatal("out of range port accepted")
				}
			}
			if value == 0 {
				t.Fatal("zero port accepted")
			}
		}
	})
}

func TestOIDCLoopbackAuthorizationModes(t *testing.T) {
	for _, mode := range []string{"GET", "POST", "request object", "form post"} {
		t.Run(mode, func(t *testing.T) {
			cfg := oidcTestConfig()
			actual := "http://127.0.0.1:43112/callback?q=registered"
			cfg.Clients = []*ClientConfig{{ClientID: "native", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1:43111/callback?q=registered"}, SkipConsent: true}}
			verifier := &unitIdentityVerifier{enabled: true}
			provider, err := NewProvider(cfg, verifier, Options{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			fixture := &providerFixture{provider: provider, config: cfg, verifier: verifier}
			cookie := responseCookie(t, fixture.login(t), provider.sessionCookie)
			sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
			params := url.Values{"client_id": {"native"}, "redirect_uri": {actual}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
			switch mode {
			case "request object":
				object := make(map[string]string)
				for k, v := range params {
					object[k] = v[0]
				}
				body, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				params = url.Values{"client_id": {"native"}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {"https://unregistered.invalid/callback"}, "request": {oidcUnsecuredObject(`{"alg":"none"}`, string(body))}}
			case "form post":
				params.Set("response_mode", "form_post")
			}
			method, path := http.MethodGet, "/oidc/authorize?"+params.Encode()
			var form url.Values
			if mode == "POST" {
				method, path, form = http.MethodPost, "/oidc/authorize", params
			}
			result := oidcUnitRequest(t, fixture, method, path, form, cookie)
			if mode == "form post" {
				if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `action="`+actual+`"`) {
					t.Fatal("form post lost actual loopback target")
				}
			} else {
				oidcUnitCode(t, result)
			}
			if len(provider.grants) != 1 {
				t.Fatal("authorization did not issue exactly one grant")
			}
			for _, grant := range provider.grants {
				if grant.request.redirectURI != actual {
					t.Fatal("grant did not retain effective raw redirect")
				}
			}
		})
	}
}
