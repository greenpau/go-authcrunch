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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestBrowserSandboxProofSelection(t *testing.T) {
	factory, err := cookie.NewFactory(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &Portal{cookie: factory}
	id := strings.Repeat("a", 36)
	name := factory.SandboxIDCookieNameForSession(id)
	base := factory.SandboxIDCookieName
	for _, tc := range []struct {
		name    string
		headers []string
		want    string
	}{
		{"exact takes precedence", []string{name + "=exact; " + base + "=legacy"}, "exact"},
		{"legacy absent exact", []string{base + "=legacy"}, "legacy"},
		{"empty exact", []string{name + "=; " + base + "=legacy"}, ""},
		{"duplicate exact", []string{name + "=exact; " + base + "=legacy", name + "=exact"}, ""},
		{"malformed exact", []string{name + "=bad\\value; " + base + "=legacy"}, ""},
		{"missing equals exact", []string{name + "; " + base + "=legacy"}, ""},
		{"duplicate legacy", []string{base + "=legacy", base + "=legacy"}, ""},
		{"empty legacy", []string{base + "="}, ""},
		{"other flow", []string{factory.SandboxIDCookieNameForSession(strings.Repeat("b", 36)) + "=exact"}, ""},
		{"missing", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://auth.example/sandbox/"+id, nil)
			for _, h := range tc.headers {
				r.Header.Add("Cookie", h)
			}
			if p.browserSandboxSecret(r, id) != tc.want {
				t.Fatal("proof selection violated exact-flow precedence")
			}
			if p.browserSandboxSecret(r, "invalid") != "" {
				t.Fatal("invalid path selected legacy proof")
			}
		})
	}
}

func browserSandboxRequest(t *testing.T, p *Portal, method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, refreshTestOrigin+target, strings.NewReader(form.Encode()))
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", refreshTestOrigin)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	if err := p.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
		t.Fatal("browser sandbox request failed")
	}
	return w
}

func TestBrowserSandboxCapacityAndConnectedAdmission(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	p := f.portal
	if err := p.sandboxes.SetMaxEntries(1); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"username": {tests.TestUser1}, "realm": {"local"}}
	start := browserSandboxRequest(t, p, http.MethodPost, "/auth/login", form)
	if start.Code != http.StatusSeeOther {
		t.Fatalf("start HTTP%d", start.Code)
	}
	var proof *http.Cookie
	for _, c := range start.Result().Cookies() {
		if strings.HasPrefix(c.Name, p.cookie.SandboxIDCookieName+"_") {
			proof = c
		}
	}
	if proof == nil {
		t.Fatal("browser start omitted independent proof")
	}
	for _, kind := range []string{"browser", "json", "connected"} {
		t.Run(kind, func(t *testing.T) {
			var w *httptest.ResponseRecorder
			switch kind {
			case "browser":
				w = browserSandboxRequest(t, p, http.MethodPost, "/auth/login", form)
			case "json":
				w = f.request(t, http.MethodPost, "/auth/login", `{"username":"`+tests.TestUser1+`","realm":"local"}`, false)
			case "connected":
				a, err := attachment.New(attachment.Config{LocalIdentityStore: "localdb"})
				if err != nil {
					t.Fatal(err)
				}
				rr := requests.NewRequest()
				rr.Upstream.BasePath = "/auth/"
				w = httptest.NewRecorder()
				err = p.beginConnectedSandbox(t.Context(), w, httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/oauth2/callback", nil), rr, a, map[string]any{"sub": "external"}, identity.RefreshIdentity{Username: tests.TestUser1, Email: tests.TestEmail1, Roles: []string{"authp/user"}}, []*user.Checkpoint{{Type: "password"}})
				if err == nil {
					t.Fatal("connected admission ignored capacity")
				}
				w.Code = rr.Response.Code
			}
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("capacity status HTTP%d", w.Code)
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == p.cookie.SandboxIDCookieName || strings.HasPrefix(c.Name, p.cookie.SandboxIDCookieName+"_") {
					t.Fatal("refusal issued proof")
				}
			}
		})
	}
	id := strings.TrimPrefix(proof.Name, p.cookie.SandboxIDCookieName+"_")
	lease, err := p.sandboxes.Acquire(id, proof.Value)
	if err != nil {
		t.Fatal("refusal invalidated earlier proof")
	}
	lease.Release()
	terminated := browserSandboxRequest(t, p, http.MethodGet, "/auth/sandbox/"+id+"/terminate", nil, proof)
	if terminated.Code != http.StatusSeeOther {
		t.Fatal("prior flow cannot terminate after capacity refusal")
	}
	if _, err := p.sandboxes.Acquire(id, proof.Value); err == nil {
		t.Fatal("terminated flow still usable")
	}
	a, err := attachment.New(attachment.Config{LocalIdentityStore: "localdb"})
	if err != nil {
		t.Fatal(err)
	}
	rr := requests.NewRequest()
	rr.Upstream.BasePath = "/auth/"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/oauth2/callback", nil)
	err = p.beginConnectedSandbox(t.Context(), w, r, rr, a, map[string]any{"sub": "external"}, identity.RefreshIdentity{Username: tests.TestUser1, Email: tests.TestEmail1, Roles: []string{"authp/user"}}, []*user.Checkpoint{{Type: "password"}})
	if err != nil || rr.Response.Code != http.StatusSeeOther {
		t.Fatal("connected admission did not recover freed capacity")
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if strings.HasPrefix(c.Name, p.cookie.SandboxIDCookieName+"_") {
			found = true
		}
	}
	if !found {
		t.Fatal("connected local factors omitted independent proof")
	}
}

func TestBrowserSandboxVisibleAdmission(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	p := f.portal
	rr := requests.NewRequest()
	rr.Upstream.BasePath = "/auth/"
	r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/login", nil)
	for i := range maxBrowserSandboxes {
		r.AddCookie(&http.Cookie{Name: p.cookie.SandboxIDCookieNameForSession(fmt.Sprintf("%036d", i)), Value: "proof"})
	}
	w := httptest.NewRecorder()
	usr := &user.User{Authenticator: user.Authenticator{TempSessionID: strings.Repeat("z", 36), TempSecret: "new-proof"}}
	if err := p.addBrowserSandbox(w, r, rr, usr); sandboxAdmissionStatus(err) != http.StatusTooManyRequests {
		t.Fatal("visible browser capacity ignored")
	}
	if len(p.sandboxes.Entries) != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("browser refusal published state or credentials")
	}
	// Duplicate names do not spend additional browser slots.
	r.Header.Del("Cookie")
	for range maxBrowserSandboxes {
		r.AddCookie(&http.Cookie{Name: p.cookie.SandboxIDCookieNameForSession(strings.Repeat("a", 36)), Value: "proof"})
	}
	if err := p.addBrowserSandbox(w, r, rr, usr); err != nil {
		t.Fatal("duplicate names exhausted browser slots")
	}
}

func TestBrowserSandboxNativeProofIsolation(t *testing.T) {
	f := newRefreshPortal(t, true, true)
	p := f.portal
	a := f.begin(t, "body")
	start := browserSandboxRequest(t, p, http.MethodPost, "/auth/login", url.Values{"username": {tests.TestUser1}, "realm": {"local"}})
	if start.Code != http.StatusSeeOther {
		t.Fatal("browser start denied beside native flow")
	}
	response := f.challenge(t, a, "body", "password", tests.TestPwd1)
	if response.Code != http.StatusOK {
		t.Fatalf("native continuation HTTP%d", response.Code)
	}
	var next apiauth.AuthResponse
	if json.Unmarshal(response.Body.Bytes(), &next) != nil || next.SandboxID != a.SandboxID || next.SandboxSecret == "" || next.SandboxSecret == a.SandboxSecret || next.Authenticated {
		t.Fatal("native challenge did not retain id and rotate independent proof")
	}
	if len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("native body continuation emitted cookies")
	}
	if _, err := p.sandboxes.Acquire(a.SandboxID, a.SandboxSecret); err == nil {
		t.Fatal("native old secret survived rotation")
	}
	lease, err := p.sandboxes.Acquire(next.SandboxID, next.SandboxSecret)
	if err != nil {
		t.Fatal("browser start invalidated native proof")
	}
	lease.Release()
}

func TestBrowserSandboxCompletionRollbackKeepsScopedDeletion(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	form := url.Values{"username": {tests.TestUser1}, "realm": {"local"}}
	starts := []*httptest.ResponseRecorder{
		browserSandboxRequest(t, p, http.MethodPost, "/auth/login?redirect_url=", form),
		browserSandboxRequest(t, p, http.MethodPost, "/auth/login?redirect_url=", form),
	}
	proofs := make([]*http.Cookie, 2)
	targets := make([]string, 2)
	for i, start := range starts {
		location, err := start.Result().Location()
		if start.Code != http.StatusSeeOther || err != nil {
			t.Fatal("rollback fixture start failed")
		}
		targets[i] = location.RequestURI()
		for _, c := range start.Result().Cookies() {
			if strings.HasPrefix(c.Name, p.cookie.SandboxIDCookieName+"_") {
				proofs[i] = c
			}
		}
		if proofs[i] == nil {
			t.Fatal("rollback fixture proof missing")
		}
	}
	password := browserSandboxRequest(t, p, http.MethodPost, targets[0], url.Values{"secret": {tests.TestPwd1}}, proofs...)
	if password.Code != http.StatusSeeOther {
		t.Fatal("rollback password checkpoint failed")
	}
	p.config.OIDCProvider = oidcTestConfig()
	if err := p.configureOIDC(); err != nil {
		t.Fatal(err)
	}
	provider := p.oidc
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p.oidc = &canceledOIDCCompletion{OpenIDProvider: provider, cancel: cancel}
	t.Cleanup(func() { p.oidc = provider })
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+targets[0], nil).WithContext(ctx)
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Origin", refreshTestOrigin)
	for _, c := range proofs {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	if err := p.ServeHTTP(ctx, w, r, requests.NewRequest()); err != nil {
		t.Fatal("rollback request failed")
	}
	if w.Code != http.StatusUnauthorized || ctx.Err() != context.Canceled {
		t.Fatalf("completion failure returned HTTP%d", w.Code)
	}
	deleted := false
	for _, c := range w.Result().Cookies() {
		if c.Name == proofs[0].Name && c.MaxAge < 0 {
			deleted = true
		}
		if c.Name == proofs[1].Name {
			t.Fatal("rollback deleted another flow proof")
		}
		if (c.Name == p.cookie.AccessTokenCookieName || c.Name == p.cookie.RefreshTokenCookieName || c.Name == p.cookie.OIDCSessionIDCookieName) && c.MaxAge >= 0 && c.Value != "" {
			t.Fatal("rollback delivered an active credential")
		}
	}
	if !deleted || w.Header().Get("Authorization") != "" {
		t.Fatal("rollback lost selected deletion or exposed token")
	}
	if lease, err := p.sandboxes.Acquire(strings.TrimPrefix(proofs[0].Name, p.cookie.SandboxIDCookieName+"_"), proofs[0].Value); err == nil {
		lease.Release()
		t.Fatal("consumed failed flow remained usable")
	}
	p.oidc = provider
	if response := browserSandboxRequest(t, p, http.MethodPost, targets[1], url.Values{"secret": {tests.TestPwd1}}, proofs[1]); response.Code != http.StatusSeeOther {
		t.Fatal("completion rollback invalidated other pending password")
	}
	if response := browserSandboxRequest(t, p, http.MethodGet, targets[1], nil, proofs[1]); response.Code != http.StatusSeeOther && response.Code != http.StatusFound {
		t.Fatalf("other flow completion HTTP%d", response.Code)
	}
}
