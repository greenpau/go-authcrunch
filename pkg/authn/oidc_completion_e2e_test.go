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

package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type capacityOIDCCompletion struct {
	oidc.OpenIDProvider
	fail atomic.Bool
}

func (p *capacityOIDCCompletion) CompleteLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, authentication oidc.Authentication) error {
	if p.fail.Load() {
		return state.ErrCapacity
	}
	return p.OpenIDProvider.CompleteLogin(ctx, w, r, authentication)
}

func TestE2EHTMLOIDCCapacityCompletionRollback(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	p.refreshStore.Close()
	p.config.RefreshTokens.MaxSessions = 1
	if err := p.configureRefresh(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := p.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Errorf("ServeHTTP returned error: %v", err)
		}
	}))
	server.StartTLS()
	defer server.Close()
	config := oidcTestConfig()
	p.config.OIDCProvider = config
	if err := p.configureOIDC(); err != nil {
		t.Fatal(err)
	}
	provider := p.oidc
	injected := &capacityOIDCCompletion{OpenIDProvider: provider}
	injected.fail.Store(true)
	p.oidc = injected
	t.Cleanup(func() { p.oidc = provider })
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	request := func(method, endpoint string, form url.Values) *http.Response {
		t.Helper()
		var body *strings.Reader
		if form == nil {
			body = strings.NewReader("")
		} else {
			body = strings.NewReader(form.Encode())
		}
		target := server.URL + endpoint
		if strings.HasPrefix(endpoint, "https://") {
			parsed, parseErr := url.Parse(endpoint)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			target = server.URL + parsed.RequestURI()
		}
		req, requestErr := http.NewRequestWithContext(t.Context(), method, target, body)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", refreshTestOrigin)
		}
		req.Host = strings.TrimPrefix(refreshTestOrigin, "https://")
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		resp.Body.Close()
		return resp
	}
	login := func() *http.Response {
		t.Helper()
		start := request(http.MethodPost, "/auth/login", url.Values{"username": {tests.TestUser1}, "realm": {"local"}})
		if start.StatusCode != http.StatusSeeOther {
			t.Fatalf("login start returned %d", start.StatusCode)
		}
		sandbox := start.Header.Get("Location")
		password := request(http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}})
		if password.StatusCode != http.StatusSeeOther {
			t.Fatalf("password checkpoint returned %d", password.StatusCode)
		}
		return request(http.MethodGet, sandbox, nil)
	}

	failed := login()
	if failed.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("capacity refusal returned %d, want %d", failed.StatusCode, http.StatusServiceUnavailable)
	}
	if authorization := failed.Header.Get("Authorization"); authorization != "" {
		t.Fatalf("capacity refusal delivered Authorization header %q", authorization)
	}
	if location := failed.Header.Get("Location"); location != "" {
		t.Fatalf("capacity refusal delivered success Location %q", location)
	}
	for _, cookie := range failed.Cookies() {
		if (cookie.Name == p.cookie.AccessTokenCookieName || cookie.Name == p.cookie.RefreshTokenCookieName || cookie.Name == p.cookie.OIDCSessionIDCookieName) && cookie.Value != "" {
			t.Fatalf("capacity refusal delivered response credential cookie %q", cookie.Name)
		}
	}
	for _, cookie := range jar.Cookies(mustParseURL(t, server.URL)) {
		if (cookie.Name == p.cookie.AccessTokenCookieName || cookie.Name == p.cookie.RefreshTokenCookieName || cookie.Name == p.cookie.OIDCSessionIDCookieName) && cookie.Value != "" {
			t.Fatalf("capacity refusal delivered credential cookie %q", cookie.Name)
		}
	}
	if len(p.sessions.Entries) != 0 {
		t.Fatal("capacity refusal leaked a portal session slot")
	}

	injected.fail.Store(false)
	retry := login()
	if retry.StatusCode != http.StatusSeeOther {
		t.Fatalf("healthy retry returned %d", retry.StatusCode)
	}
	if len(p.sessions.Entries) != 1 {
		t.Fatalf("healthy retry retained %d portal sessions, want 1", len(p.sessions.Entries))
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestE2EHTMLSessionCacheCapacityRollback(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	p.refreshStore.Close()
	p.config.RefreshTokens.MaxSessions = 1
	if err := p.configureRefresh(); err != nil {
		t.Fatal(err)
	}
	preloadID := preloadSessionCacheNearCapacity(t, p)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveErr := p.ServeHTTP(r.Context(), w, r, requests.NewRequest()); serveErr != nil {
			t.Errorf("ServeHTTP returned error: %v", serveErr)
		}
	}))
	server.StartTLS()
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	client.Timeout = 60 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(method, endpoint string, form url.Values) *http.Response {
		t.Helper()
		target := server.URL + endpoint
		if strings.HasPrefix(endpoint, "https://") {
			parsed, parseErr := url.Parse(endpoint)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			target = server.URL + parsed.RequestURI()
		}
		body := strings.NewReader("")
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, requestErr := http.NewRequestWithContext(t.Context(), method, target, body)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Host = strings.TrimPrefix(refreshTestOrigin, "https://")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", refreshTestOrigin)
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		resp.Body.Close()
		return resp
	}
	login := func() *http.Response {
		start := request(http.MethodPost, "/auth/login", url.Values{"username": {tests.TestUser1}, "realm": {"local"}})
		if start.StatusCode != http.StatusSeeOther {
			t.Fatalf("login start returned %d", start.StatusCode)
		}
		sandbox := start.Header.Get("Location")
		password := request(http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}})
		if password.StatusCode != http.StatusSeeOther {
			t.Fatalf("password checkpoint returned %d", password.StatusCode)
		}
		return request(http.MethodGet, sandbox, nil)
	}

	failed := login()
	if failed.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("cache capacity refusal returned %d, want %d", failed.StatusCode, http.StatusServiceUnavailable)
	}
	if failed.Header.Get("Authorization") != "" || failed.Header.Get("Location") != "" {
		t.Fatal("cache capacity refusal delivered credential headers")
	}
	for _, cookie := range failed.Cookies() {
		if (cookie.Name == p.cookie.AccessTokenCookieName || cookie.Name == p.cookie.RefreshTokenCookieName) && cookie.Value != "" {
			t.Fatalf("cache capacity refusal delivered credential cookie %q", cookie.Name)
		}
	}
	if err = p.sessions.Delete(preloadID); err != nil {
		t.Fatal(err)
	}
	retry := login()
	if retry.StatusCode != http.StatusSeeOther {
		t.Fatalf("healthy retry returned %d", retry.StatusCode)
	}
	var oldRefresh *http.Cookie
	for _, cookie := range retry.Cookies() {
		if cookie.Name == p.cookie.RefreshTokenCookieName && cookie.Value != "" {
			copy := *cookie
			oldRefresh = &copy
		}
	}
	if oldRefresh == nil {
		t.Fatal("healthy login did not establish refresh cookie")
	}
	record, err := storageRecordForPortal(t, p)
	if err != nil {
		t.Fatal(err)
	}
	preloadID = fillSessionCacheNearCapacity(t, p, record)
	refresh := func(httpClient *http.Client, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth/api/refresh_token", strings.NewReader("{}"))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Host = strings.TrimPrefix(refreshTestOrigin, "https://")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", refreshTestOrigin)
		req.Header.Set(refreshRequestHeader, "1")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, requestErr := httpClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		resp.Body.Close()
		return resp
	}
	failedRefresh := refresh(client, nil)
	if failedRefresh.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("post-rotation cache refusal returned %d, want %d", failedRefresh.StatusCode, http.StatusServiceUnavailable)
	}
	if failedRefresh.Header.Get("Authorization") != "" || failedRefresh.Header.Get("Location") != "" {
		t.Fatal("post-rotation cache refusal delivered credential headers")
	}
	for _, cookie := range failedRefresh.Cookies() {
		if (cookie.Name == p.cookie.AccessTokenCookieName || cookie.Name == p.cookie.RefreshTokenCookieName) && cookie.Value != "" {
			t.Fatalf("post-rotation cache refusal delivered credential cookie %q", cookie.Name)
		}
	}
	if err = p.sessions.Delete(preloadID); err != nil {
		t.Fatal(err)
	}
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if recovered := login(); recovered.StatusCode != http.StatusSeeOther {
		t.Fatalf("fresh login after refresh cleanup returned %d", recovered.StatusCode)
	}
	isolated := &http.Client{Transport: client.Transport, Timeout: 5 * time.Second}
	if replay := refresh(isolated, oldRefresh); replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("spent pre-failure credential returned %d", replay.StatusCode)
	}
	if current := refresh(client, nil); current.StatusCode != http.StatusOK {
		t.Fatalf("replay of old credential affected new family: refresh returned %d", current.StatusCode)
	}
}

func preloadSessionCacheNearCapacity(t *testing.T, p *Portal) string {
	t.Helper()
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		_ = storage.Close()
	})
	binding, err := state.Binding(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.ConfigurePersistentState(storage, binding); err != nil {
		t.Fatal(err)
	}
	record, err := storage.OpenRecord("portal-sessions/"+p.config.Name, binding)
	if err != nil {
		t.Fatal(err)
	}
	return fillSessionCacheNearCapacity(t, p, record)
}

func storageRecordForPortal(t *testing.T, p *Portal) (*state.Record, error) {
	t.Helper()
	binding, err := state.Binding(p.config)
	if err != nil {
		return nil, err
	}
	return p.state.OpenRecord("portal-sessions/"+p.config.Name, binding)
}

func fillSessionCacheNearCapacity(t *testing.T, p *Portal, record *state.Record) string {
	t.Helper()
	preloadID := strings.Repeat("p", 32)
	// Synthetic trusted padding stands in for many ordinary accumulated sessions
	// without repeatedly writing a growing 64 MiB snapshot. No HTTP request can
	// submit this value; the capacity trigger remains a normal browser login.
	newPreload := func(size int) *user.User {
		u, createErr := user.NewUser(map[string]any{"sub": "preload", "jti": preloadID, "exp": time.Now().Add(time.Hour).Unix(), "blob": strings.Repeat("x", size)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return u
	}
	const initialSize = 60 << 20
	if err := p.sessions.Add(preloadID, newPreload(initialSize)); err != nil {
		t.Fatal(err)
	}
	raw, err := record.Load()
	if err != nil {
		t.Fatal(err)
	}
	padding := initialSize + ((64 << 20) - 512 - len(raw))
	for {
		err = p.sessions.Add(preloadID, newPreload(padding))
		if err == nil {
			return preloadID
		}
		if !errors.Is(err, state.ErrCapacity) || padding < initialSize {
			t.Fatal("preload near-capacity session", err)
		}
		padding -= 1024
	}
}
