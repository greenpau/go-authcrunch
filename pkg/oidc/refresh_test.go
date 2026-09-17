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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func oidcRefreshRequest(t *testing.T, f *providerFixture, token, client, scope string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	if scope != "" {
		form.Set("scope", scope)
	}
	r := httptest.NewRequest("POST", oidcTestOrigin+"/auth/oidc/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(client, strings.Repeat("s", 32))
	w := httptest.NewRecorder()
	f.provider.ServeHTTP(w, r)
	return w
}
func oidcRefreshFixture(t *testing.T, configure ...func(*Provider)) (*providerFixture, map[string]any) {
	t.Helper()
	f := newProviderFixture(t)
	o := f.provider
	for _, apply := range configure {
		apply(o)
	}
	o.clients["client"].Scopes = []string{"openid", "profile", "offline_access"}
	second := cloneClientConfig(*o.clients["client"])
	second.ClientID = "second"
	o.clients["second"] = second
	cookie := responseCookie(t, f.login(t), o.sessionCookie)
	// Seed an approved authorization through the same transaction as code issuance;
	// browser consent itself is exercised by the portal E2E test.
	session := sha256.Sum256([]byte(cookie.Value))
	r := &oidcAuthorization{clientID: "client", redirectURI: "https://client.example.test/callback", scopes: []string{"openid", "profile", "offline_access"}, session: session, nonce: "original"}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", oidcTestOrigin+"/auth/oidc/authorize", nil)
	o.mu.Lock()
	buffered := &oidcHTTPResponse{header: make(http.Header)}
	o.issueCode(buffered, req, r)
	o.mu.Unlock()
	o.sendResponse(w, req, buffered, true)
	code := oidcUnitCode(t, w)
	response := oidcUnitToken(t, f, code)
	if response.Code != 200 {
		t.Fatal("offline code exchange failed")
	}
	tokens := oidcUnitJSON(t, response)
	tokens["code"] = code
	return f, tokens
}
func oidcUnitJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var data map[string]any
	if json.Unmarshal(w.Body.Bytes(), &data) != nil {
		t.Fatal("invalid response JSON")
	}
	return data
}
func TestOIDCRefreshSecurity(t *testing.T) {
	for _, boundary := range []string{"rotation", "wrong client", "scope escalation", "scope narrowing", "replay", "code replay", "revocation", "identity revoked", "logout", "expiry", "capacity", "close", "concurrent"} {
		t.Run(boundary, func(t *testing.T) {
			f, tokens := oidcRefreshFixture(t)
			o := f.provider
			old := tokens["refresh_token"].(string)
			if len(old) != 43 {
				t.Fatal("refresh token missing entropy")
			}
			switch boundary {
			case "wrong client":
				if oidcRefreshRequest(t, f, old, "second", "").Code != 400 {
					t.Fatal("client binding bypass")
				}
			case "scope escalation":
				if oidcRefreshRequest(t, f, old, "client", "openid email").Code != 400 {
					t.Fatal("scope increased")
				}
			case "capacity":
				o.config.MaxRefreshTokens = 1
				if oidcRefreshRequest(t, f, old, "client", "").Code != 503 {
					t.Fatal("replay evidence evicted at capacity")
				}
				o.config.MaxRefreshTokens = 2
			case "identity revoked":
				f.verifier.enabled = false
			case "logout":
				clear(o.sessions)
			case "expiry":
				o.now = func() time.Time { return time.Now().Add(24 * time.Hour) }
			case "close":
				o.Close()
			case "revocation":
				o.revokeGrant(o.refresh[sha256.Sum256([]byte(old))])
			case "code replay":
				if oidcUnitToken(t, f, tokens["code"].(string)).Code != 400 {
					t.Fatal("code replay accepted")
				}
			case "concurrent":
				var wg sync.WaitGroup
				codes := make(chan int, 2)
				for range 2 {
					wg.Go(func() { codes <- oidcRefreshRequest(t, f, old, "client", "").Code })
				}
				wg.Wait()
				close(codes)
				success := 0
				for status := range codes {
					if status == 200 {
						success++
					} else if status != 400 {
						t.Fatal("unexpected concurrent result")
					}
				}
				if success != 1 || len(o.access) != 0 {
					t.Fatal("concurrent replay did not revoke family")
				}
				return
			}
			scope := ""
			if boundary == "scope narrowing" {
				scope = "openid"
			}
			response := oidcRefreshRequest(t, f, old, "client", scope)
			switch boundary {
			case "identity revoked", "logout", "expiry", "close", "revocation", "code replay":
				if response.Code != 400 && response.Code != 503 {
					t.Fatal("revoked refresh accepted")
				}
				return
			}
			if response.Code != 200 {
				t.Fatalf("refresh failed: %d", response.Code)
			}
			fresh := oidcUnitJSON(t, response)
			if fresh["refresh_token"] == old || fresh["access_token"] == tokens["access_token"] {
				t.Fatal("credentials not rotated")
			}
			if scope != "" && fresh["scope"] != "openid" {
				t.Fatal("narrowing ignored")
			}
			if boundary == "scope narrowing" && oidcRefreshRequest(t, f, fresh["refresh_token"].(string), "client", "openid profile").Code != 400 {
				t.Fatal("narrowing reversible")
			}
			if oidcRefreshRequest(t, f, old, "client", "").Code != 400 || oidcRefreshRequest(t, f, fresh["refresh_token"].(string), "client", "").Code != 400 || len(o.access) != 0 {
				t.Fatal("replay did not revoke descendants")
			}
			if len(o.refresh) != 2 {
				t.Fatal("spent evidence lost")
			}
		})
	}
}
func TestOIDCOfflineRequiresConsent(t *testing.T) {
	f := newProviderFixture(t)
	client := f.provider.clients["client"]
	client.Scopes = append(client.Scopes, "offline_access")
	params := url.Values{"response_type": {"code"}, "scope": {"openid offline_access"}}
	for _, prompt := range []string{"", "none", "consent"} {
		params.Set("prompt", prompt)
		r := &oidcAuthorization{}
		if code := f.provider.validateAuthorization(r, client, params); code != "" {
			t.Fatal(code)
		}
		if slices.Contains(r.scopes, "offline_access") != (prompt == "consent") {
			t.Fatal("offline access without explicit consent")
		}
	}
}

func TestOIDCRefreshAbsoluteDeadline(t *testing.T) {
	now := time.Now()
	f, tokens := oidcRefreshFixture(t, func(o *Provider) { o.config.RefreshLifetimeSeconds = 2; o.now = func() time.Time { return now } })
	if tokens["expires_in"] != float64(2) {
		t.Fatal("access lifetime exceeds family deadline")
	}
	old := tokens["refresh_token"].(string)
	now = now.Add(time.Second)
	response := oidcRefreshRequest(t, f, old, "client", "profile")
	if response.Code != 200 {
		t.Fatal("refresh failed")
	}
	fresh := oidcUnitJSON(t, response)
	if fresh["expires_in"] != float64(1) || fresh["id_token"] != nil {
		t.Fatal("refresh extended deadline or emitted unrequested ID token")
	}
	now = now.Add(time.Second)
	if oidcRefreshRequest(t, f, fresh["refresh_token"].(string), "client", "").Code != 400 {
		t.Fatal("expired family accepted")
	}
	if len(f.provider.refresh) != 0 || len(f.provider.access) != 0 {
		t.Fatal("expired family state not reclaimed")
	}
}
