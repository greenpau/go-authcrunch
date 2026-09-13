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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const oidcTestOrigin = "https://auth.example.test"

type providerFixture struct {
	provider *Provider
	config   *Config
	verifier *unitIdentityVerifier
}
type unitIdentityVerifier struct{ enabled bool }

func (v *unitIdentityVerifier) WithIdentity(ctx context.Context, proof Authentication, apply func(Identity) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !v.enabled || proof.Realm != "local" || proof.Backend != "localdb" || proof.Username != "alice" || proof.Evidence.UserID != "immutable-user" || proof.Evidence.BackendVersion != "v1" || proof.Evidence.CredentialVersion != 1 {
		return ErrIdentityDenied
	}
	return apply(Identity{Username: "alice", Name: "Alice", Email: "alice@example.test"})
}
func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	config := oidcTestConfig()
	config.Clients[0].SkipConsent = true
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	verifier := &unitIdentityVerifier{enabled: true}
	provider, err := NewProvider(config, verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	return &providerFixture{provider: provider, config: config, verifier: verifier}
}
func (f *providerFixture) login(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", oidcTestOrigin+"/auth/login", nil)
	r.Header.Set("Origin", oidcTestOrigin)
	proof := Authentication{Realm: "local", Backend: "localdb", Username: "alice", Methods: []string{"pwd"}, Evidence: requests.AuthenticationEvidence{UserID: "immutable-user", BackendVersion: "v1", CredentialVersion: 1, AuthenticatedAt: f.provider.now().Unix(), Method: "password"}}
	w := httptest.NewRecorder()
	if err := f.provider.CompleteLogin(t.Context(), w, r, proof); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}
	return w
}
func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatalf("missing %s cookie", name)
	return nil
}
func TestOIDCContinuationAuthenticationAge(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prompt  bool
		maxAge  *int64
		age     int64
		allowed bool
	}{
		{"earlier forced login", true, nil, 2, false},
		{"current forced login", true, nil, 0, true},
		{"earlier max_age zero", false, new(int64(0)), 2, false},
		{"current max_age zero", false, new(int64(0)), 0, true},
		{"stale max_age", false, new(int64(1)), 2, false},
		{"recent max_age", false, new(int64(5)), 2, true},
		{"no freshness requirement", false, nil, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProviderFixture(t)
			o := f.provider
			login := f.login(t)
			cookie := responseCookie(t, login, o.sessionCookie)
			hash := sha256.Sum256([]byte(cookie.Value))
			session := o.sessions[hash]
			pending := oidcRandom()
			o.pending[sha256.Sum256([]byte(pending))] = &oidcAuthorization{clientID: "client", redirectURI: "https://client.example.test/callback", scopes: []string{"openid"}, session: hash, created: time.Unix(session.proof.AuthenticatedAt+tc.age, 0), expires: o.now().Add(time.Minute), promptLogin: tc.prompt, maxAge: tc.maxAge}
			r := httptest.NewRequest("GET", oidcTestOrigin+"/auth/oidc/continue", nil)
			r.AddCookie(cookie)
			r.AddCookie(&http.Cookie{Name: o.requestCookie, Value: pending})
			w := httptest.NewRecorder()
			f.provider.ServeHTTP(w, r)
			target, _ := url.Parse(w.Header().Get("Location"))
			if tc.allowed {
				_ = oidcUnitCode(t, w)
			} else if target.Query().Get("error") != "login_required" || target.Query().Get("code") != "" {
				t.Fatal("stale login satisfied authorization freshness")
			}
		})
	}
}

func oidcUnitRequest(t *testing.T, f *providerFixture, method, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, oidcTestOrigin+"/auth"+path, strings.NewReader(form.Encode()))
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.provider.ServeHTTP(w, r)
	return w
}

func oidcUnitAuthorize(t *testing.T, f *providerFixture, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}}.Encode(), nil, cookie)
}

func oidcUnitCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 || u.Query().Get("code") == "" {
		t.Fatal("code not issued")
	}
	return u.Query().Get("code")
}

func oidcUnitToken(t *testing.T, f *providerFixture, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example.test/callback"}}
	r := httptest.NewRequest("POST", oidcTestOrigin+"/auth/oidc/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("client", strings.Repeat("s", 32))
	w := httptest.NewRecorder()
	f.provider.ServeHTTP(w, r)
	return w
}

func TestOIDCLifetimesAndCapacity(t *testing.T) {
	for _, boundary := range []string{"code", "session", "token", "subsecond expiry", "pending", "grant-capacity", "pending-capacity", "session-capacity", "close"} {
		t.Run(boundary, func(t *testing.T) {
			f := newProviderFixture(t)
			o := f.provider
			now := time.Now()
			o.now = func() time.Time { return now }
			login := f.login(t)
			if login.Code != 200 {
				t.Fatal("login failed")
			}
			session := responseCookie(t, login, o.sessionCookie)
			if session.Name != "AUTHP_OIDC_SESSION_ID" || session.Path != "/auth" || !session.Secure || !session.HttpOnly || session.Domain != "" || session.SameSite != http.SameSiteLaxMode {
				t.Fatal("unsafe provider cookie")
			}
			code := oidcUnitCode(t, oidcUnitAuthorize(t, f, session))
			switch boundary {
			case "subsecond expiry":
				hash := sha256.Sum256([]byte(session.Value))
				o.sessions[hash].expires = now.Add(time.Second)
				now = now.Add(900 * time.Millisecond)
				// Choose a deadline/current time within the same numeric-date second.
				o.sessions[hash].expires = time.Unix(now.Unix(), 999999999)
				if w := oidcUnitToken(t, f, code); w.Code != 400 {
					t.Fatal("zero-lifetime token issued")
				}
			case "code":
				now = now.Add(oidcCodeLifetime * time.Second)
				if w := oidcUnitToken(t, f, code); w.Code != 400 {
					t.Fatal("expired code redeemed")
				}
			case "session":
				now = now.Add(time.Duration(o.config.SessionLifetimeSeconds) * time.Second)
				params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}}
				w := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, session)
				target, _ := url.Parse(w.Header().Get("Location"))
				if target.Query().Get("error") != "login_required" {
					t.Fatal("expired browser session reused")
				}
			case "token":
				w := oidcUnitToken(t, f, code)
				if w.Code != 200 {
					t.Fatal("token not issued")
				}
				var tokens map[string]any
				if json.Unmarshal(w.Body.Bytes(), &tokens) != nil {
					t.Fatal("invalid token response")
				}
				now = now.Add(time.Duration(o.config.TokenLifetimeSeconds) * time.Second)
				w = oidcUnitRequest(t, f, "POST", "/oidc/userinfo", url.Values{"access_token": {tokens["access_token"].(string)}}, nil)
				if w.Code != 401 {
					t.Fatal("expired access token accepted")
				}
			case "pending":
				w := oidcUnitAuthorize(t, f, nil)
				pending := responseCookie(t, w, o.requestCookie)
				now = now.Add(oidcRequestLifetime * time.Second)
				if w := oidcUnitRequest(t, f, "GET", "/oidc/continue", nil, pending); w.Code != 400 {
					t.Fatal("expired continuation accepted")
				}
			case "grant-capacity":
				o.config.MaxGrants = 1
				w := oidcUnitAuthorize(t, f, session)
				target, _ := url.Parse(w.Header().Get("Location"))
				if target.Query().Get("error") != "temporarily_unavailable" {
					t.Fatal("grant capacity not enforced")
				}
				now = now.Add(time.Duration(oidcCodeLifetime+o.config.TokenLifetimeSeconds) * time.Second)
				_ = oidcUnitCode(t, oidcUnitAuthorize(t, f, session))
			case "pending-capacity":
				o.config.MaxPendingRequests = 1
				if w := oidcUnitAuthorize(t, f, nil); w.Code != 303 {
					t.Fatal("first pending request failed")
				}
				w := oidcUnitAuthorize(t, f, nil)
				target, _ := url.Parse(w.Header().Get("Location"))
				if target.Query().Get("error") != "temporarily_unavailable" {
					t.Fatal("pending capacity not enforced")
				}
			case "session-capacity":
				o.config.MaxSessions = 1
				if w := f.login(t); w.Code == 200 {
					t.Fatal("session capacity not enforced")
				}
			case "close":
				f.provider.Close()
				f.provider.Close()
				if w := oidcUnitToken(t, f, code); w.Code != 503 {
					t.Fatal("closed provider issued tokens")
				}
				if len(o.sessions)+len(o.grants)+len(o.pending)+len(o.access) != 0 {
					t.Fatal("closed provider retained state")
				}
			}
		})
	}
}

func TestOIDCIdentityAndIsolation(t *testing.T) {
	f := newProviderFixture(t)
	o := f.provider
	login := f.login(t)
	session := responseCookie(t, login, o.sessionCookie)
	code := oidcUnitCode(t, oidcUnitAuthorize(t, f, session))
	f.verifier.enabled = false
	if w := oidcUnitToken(t, f, code); w.Code != 400 {
		t.Fatal("disabled user redeemed code")
	}
	// A caller modifying its original config cannot change a registered grant.
	f.config.Clients[0].RedirectURIs[0] = "https://evil.example/callback"
	if o.clients["client"].RedirectURIs[0] != "https://client.example.test/callback" {
		t.Fatal("OIDC runtime shares mutable caller configuration")
	}
	if oidcCookieHash(httptest.NewRequest("GET", "https://auth.test", nil), o.sessionCookie) != ([32]byte{}) {
		t.Fatal("absent cookie has identity")
	}
	request := httptest.NewRequest("GET", "https://auth.test", nil)
	request.AddCookie(session)
	request.AddCookie(session)
	if oidcCookieHash(request, o.sessionCookie) != ([32]byte{}) {
		t.Fatal("ambiguous cookie accepted")
	}
}

func TestOIDCKeys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   []string
		content string
		invalid bool
	}{
		{"RSA", []string{"../../testdata/rskeys/test_2_pri.pem"}, "", false},
		{"rotation", []string{"../../testdata/rskeys/test_2_pri.pem", "../../testdata/rskeys/test_1_pri.pem"}, "", false},
		{"duplicate material", []string{"../../testdata/rskeys/test_2_pri.pem", "../../testdata/rskeys/test_2_pri.pem"}, "", true},
		{"missing", []string{"missing-oidc.pem"}, "", true},
		{"public key", []string{"../../testdata/rskeys/test_2_pub.pem"}, "", true},
		{"EC key", []string{"../../testdata/ecdsakeys/test_2_pri.pem"}, "", true},
		{"garbage", nil, "not a private key", true},
		{"oversized", nil, strings.Repeat("x", 65537), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := oidcTestConfig()
			c.SigningKeyFiles = tc.files
			if tc.content != "" {
				name := filepath.Join(t.TempDir(), "key.pem")
				if err := os.WriteFile(name, []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
				c.SigningKeyFiles = []string{name}
			}
			keys, err := loadSigningKeys(c.SigningKeyFiles, nil)
			if (err != nil) != tc.invalid {
				t.Fatalf("invalid = %v, expected %v", err != nil, tc.invalid)
			}
			if err == nil {
				provider := &Provider{keys: keys, config: *c}
				raw, err := provider.sign(map[string]any{"iss": c.Issuer, "sub": "immutable", "aud": "client", "exp": 1})
				if err != nil {
					t.Fatal(err)
				}
				if subject, err := provider.hintSubject(raw, "client"); err != nil || subject != "immutable" {
					t.Fatal("valid expired hint rejected")
				}
				if _, err := provider.hintSubject(raw, "other-client"); err == nil {
					t.Fatal("hint audience ignored")
				}
				digest := sha256.Sum256([]byte("untrusted"))
				parts := strings.Split(raw, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(digest[:])
				if _, err := provider.hintSubject(strings.Join(parts, "."), "client"); err == nil {
					t.Fatal("tampered hint accepted")
				}
				if len(keys) == 2 {
					provider.keys[0], provider.keys[1] = provider.keys[1], provider.keys[0]
					if _, err := provider.hintSubject(raw, "client"); err != nil {
						t.Fatal("rotation changed retained key identity")
					}
				}
			}
		})
	}
}

type oidcLockCheckingWriter struct {
	*httptest.ResponseRecorder
	provider *Provider
	unlocked bool
}

func (w *oidcLockCheckingWriter) Write(body []byte) (int, error) {
	w.unlocked = w.provider.mu.TryLock()
	if w.unlocked {
		w.provider.mu.Unlock()
	}
	return w.ResponseRecorder.Write(body)
}
func TestOIDCNetworkWritesReleaseStateLock(t *testing.T) {
	f := newProviderFixture(t)
	o := f.provider
	login := f.login(t)
	cookie := responseCookie(t, login, o.sessionCookie)
	params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}}
	r := httptest.NewRequest("GET", o.config.Issuer+"/oidc/authorize?"+params.Encode(), nil)
	r.AddCookie(cookie)
	w := &oidcLockCheckingWriter{ResponseRecorder: httptest.NewRecorder(), provider: o}
	f.provider.ServeHTTP(w, r)
	if w.Code != 302 || !w.unlocked {
		t.Fatal("network response held provider lock")
	}
}

func FuzzOIDCAuthorizationParameters(f *testing.F) {
	for _, seed := range []string{"client_id=c&response_type=code&scope=openid", "redirect_uri=https%3A%2F%2Frp.test%2Fcb", "client_id=c&client_id=d", "request_uri=http://127.0.0.1/", "a=%xx"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > oidcMaxRequestBytes+1 {
			return
		}
		r := httptest.NewRequest("POST", "https://auth.test/oidc/authorize", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		values, err := oidcParameters(httptest.NewRecorder(), r, false)
		if err != nil {
			return
		}
		for _, entries := range values {
			if len(entries) != 1 {
				t.Fatal("parser accepted duplicate values")
			}
		}
		o := &Provider{}
		client := &ClientConfig{Scopes: []string{"openid", "profile", "email"}}
		request := &oidcAuthorization{}
		// Hints require configured crypto and are exercised by the signed-key tests.
		values.Del("id_token_hint")
		_ = o.validateAuthorization(request, client, values)
	})
}

func TestProviderLoginEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Authentication, *http.Request)
	}{
		{"missing backend", func(p *Authentication, _ *http.Request) { p.Backend = "" }},
		{"missing username", func(p *Authentication, _ *http.Request) { p.Username = "" }},
		{"missing immutable identity", func(p *Authentication, _ *http.Request) { p.Evidence.UserID = "" }},
		{"missing authentication time", func(p *Authentication, _ *http.Request) { p.Evidence.AuthenticatedAt = 0 }},
		{"invalid authentication time", func(p *Authentication, _ *http.Request) { p.Evidence.AuthenticatedAt = -1 }},
		{"missing methods", func(p *Authentication, _ *http.Request) { p.Methods = nil }},
		{"stale credential", func(p *Authentication, _ *http.Request) { p.Evidence.CredentialVersion = 2 }},
		{"stale backend", func(p *Authentication, _ *http.Request) { p.Evidence.BackendVersion = "old" }},
		{"foreign origin", func(_ *Authentication, r *http.Request) { r.Header.Set("Origin", "https://other.test") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProviderFixture(t)
			proof := Authentication{Realm: "local", Backend: "localdb", Username: "alice", Methods: []string{"pwd"}, Evidence: requests.AuthenticationEvidence{UserID: "immutable-user", BackendVersion: "v1", CredentialVersion: 1, AuthenticatedAt: time.Now().Unix()}}
			r := httptest.NewRequest("POST", oidcTestOrigin+"/auth/login", nil)
			r.Header.Set("Origin", oidcTestOrigin)
			tc.mutate(&proof, r)
			w := httptest.NewRecorder()
			if err := f.provider.CompleteLogin(t.Context(), w, r, proof); err == nil {
				t.Fatal("invalid login evidence accepted")
			}
			if len(f.provider.sessions) != 0 {
				t.Fatal("invalid evidence allocated a session")
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.MaxAge > 0 {
					t.Fatal("invalid evidence issued a browser credential")
				}
			}
		})
	}
}
