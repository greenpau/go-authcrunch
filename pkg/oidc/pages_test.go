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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestOIDCBrowserErrorNegotiation(t *testing.T) {
	f := newProviderFixture(t)
	for _, tc := range []struct {
		accept string
		html   bool
	}{
		{"", false}, {"*/*", false}, {"application/json", false},
		{"text/html", true}, {"text/html,application/xhtml+xml,*/*;q=0.8", true},
		{"text/html;q=0", false}, {"text/html;q=0.2,application/json", false},
		{"text/html;q=0.9,application/json;q=0.2", true},
		{"text/html;q=NaN", false}, {"text/html;q=2", false}, {"text/html;q=bad", false},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			for _, endpoint := range []string{"/oidc/authorize", "/oidc/continue", "/oidc/token", "/oidc/userinfo"} {
				r := httptest.NewRequest("GET", oidcTestOrigin+"/auth"+endpoint, nil)
				r.Header.Set("Accept", tc.accept)
				w := httptest.NewRecorder()
				f.provider.ServeHTTP(w, r)
				browser := endpoint == "/oidc/authorize" || endpoint == "/oidc/continue"
				isHTML := strings.HasPrefix(w.Header().Get("Content-Type"), "text/html")
				if isHTML != (browser && tc.html) {
					t.Fatalf("wrong response format for %s", endpoint)
				}
				if w.Code < 400 {
					t.Fatal("error status lost")
				}
				if isHTML && (!strings.Contains(w.Body.String(), "Unable to continue") || strings.Contains(w.Body.String(), "<form")) {
					t.Fatal("unsafe error page")
				}
				if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
					t.Fatal("error protection lost")
				}
			}
		})
	}
	f.provider.Close()
	r := httptest.NewRequest("HEAD", oidcTestOrigin+"/auth/oidc/authorize", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	f.provider.ServeHTTP(w, r)
	if w.Code != 503 || w.Body.Len() != 0 {
		t.Fatal("HEAD error body or status changed")
	}
}

func TestOIDCBrowserErrorMultipleAcceptHeaders(t *testing.T) {
	f := newProviderFixture(t)
	for _, tc := range []struct {
		name   string
		accept []string
		html   bool
	}{
		{"html on second line", []string{"application/json;q=0.2", "text/html"}, true},
		{"json on second line", []string{"text/html;q=0.2", "application/json"}, false},
		{"html disabled", []string{"application/json;q=0.2", "text/html;q=0"}, false},
		{"equal quality", []string{"application/json", "text/html"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, oidcTestOrigin+"/auth/oidc/continue", nil)
			r.Header["Accept"] = tc.accept
			w := httptest.NewRecorder()
			f.provider.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") != tc.html {
				t.Fatal("repeated Accept fields changed error negotiation")
			}
			if w.Header().Get("Vary") != "Accept" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("negotiated error lost its response policy")
			}
		})
	}
}

func TestOIDCConsentPresentation(t *testing.T) {
	f := newProviderFixture(t)
	o := f.provider
	o.clients["client"].SkipConsent = false
	o.clients["client"].ClientName = `<img src=x onerror=alert(1)>`
	o.clients["client"].Scopes = []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	session := responseCookie(t, f.login(t), o.sessionCookie)
	params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid profile email address phone offline_access"}, "prompt": {"consent"}, "claims": {`{"userinfo":{"name":null,"auth_time":null},"id_token":{"given_name":null,"acr":null}}`}}
	w := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, session)
	if w.Code != 200 {
		t.Fatal("consent missing")
	}
	body := w.Body.String()
	for _, expected := range []string{"Account identifier", "Profile information", "Email address", "Postal address", "Phone number", "Continued access", "Sign-in time", "Given name", "Sign-in assurance", `value="allow"`, `value="deny"`, `action="https://auth.example.test/auth/oidc/continue"`, "&lt;img"} {
		if !strings.Contains(body, expected) {
			t.Errorf("missing consent content %q", expected)
		}
	}
	for _, forbidden := range []string{"<img src=x", "userinfo:", "id_token:", "Approved permissions", "Full name", "<script"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("unexpected consent content %q", forbidden)
		}
	}
	match := regexp.MustCompile(`<style nonce="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "'nonce-"+match[1]+"'") {
		t.Fatal("standalone stylesheet blocked by CSP")
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self' https://client.example.test") {
		t.Fatal("native consent form cannot complete its registered redirect")
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatal("inline execution allowed")
	}
	for _, names := range oidcScopeClaims {
		for _, name := range names {
			if oidcClaimLabel(name) == name {
				t.Errorf("missing readable label for %s", name)
			}
		}
	}
	if oidcClaimLabel("extension") != "extension" {
		t.Fatal("unknown label not preserved")
	}
}

func TestOIDCPageRenderer(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			config := oidcTestConfig()
			var provider *Provider
			called := false
			var err error
			provider, err = NewProvider(config, &unitIdentityVerifier{enabled: true}, Options{RenderPage: func(_ context.Context, page Page) ([]byte, error) {
				called = true
				if !provider.mu.TryLock() {
					t.Fatal("renderer called under provider lock")
				}
				provider.mu.Unlock()
				if page.Kind != "error" || page.BasePath != "/auth" || page.Nonce == "" {
					t.Fatal("incomplete page data")
				}
				if fail {
					return []byte("partial-secret-output"), fmt.Errorf("private-template-error")
				}
				return []byte("<!doctype html><title>Custom error</title>"), nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			r := httptest.NewRequest("GET", oidcTestOrigin+"/auth/oidc/continue", nil)
			r.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()
			provider.ServeHTTP(w, r)
			if !called {
				t.Fatal("custom renderer ignored")
			}
			if fail {
				if w.Code != 500 || strings.TrimSpace(w.Body.String()) != `{"error":"server_error"}` || w.Header().Get("Content-Type") != "application/json" {
					t.Fatal("render failure leaked output or lost its status")
				}
			} else if w.Code != 400 || !strings.Contains(w.Body.String(), "Custom error") {
				t.Fatal("custom page or original status missing")
			}
		})
	}
}

func TestOIDCFormPostPresentation(t *testing.T) {
	f := newProviderFixture(t)
	session := responseCookie(t, f.login(t), f.provider.sessionCookie)
	params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "response_mode": {"form_post"}, "state": {`</script><img src=x onerror=alert(1)>`}}
	previousNonce := ""
	for _, failure := range []bool{false, true} {
		if failure {
			params.Set("response_type", "invalid")
		}
		w := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, session)
		body := w.Body.String()
		nonce := regexp.MustCompile(`<script nonce="([^"]+)"`).FindStringSubmatch(body)
		if w.Code != 200 || len(nonce) != 2 || nonce[1] == previousNonce {
			t.Fatal("missing or reused nonce")
		}
		previousNonce = nonce[1]
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'nonce-"+nonce[1]+"'") || !strings.Contains(csp, "form-action https://client.example.test") {
			t.Fatal("form-post policy lost")
		}
		if strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;/script&gt;") || !strings.Contains(body, "<noscript>") {
			t.Fatal("escaping or manual continuation lost")
		}
		field := `name="code"`
		if failure {
			field = `name="error"`
		}
		if !strings.Contains(body, field) || !strings.Contains(body, `id="response" method="post" action="https://client.example.test/callback"`) {
			t.Fatal("protocol form lost")
		}
	}
}
