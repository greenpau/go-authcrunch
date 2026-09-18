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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func TestRefererCookieCleanupHandlers(t *testing.T) {
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.test", "prefix", "/")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("portal screen", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			value string
			code  int
		}{
			{"trusted", "https://app.example.test/dashboard", http.StatusSeeOther},
			{"untrusted", "https://untrusted.example.test/dashboard", http.StatusOK},
			{"malformed", "%", http.StatusOK},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p := newRefererCleanupPortal(t, trusted)
				r := httptest.NewRequest(http.MethodGet, "https://login.example.test/auth/portal", nil)
				r.AddCookie(&http.Cookie{Name: p.cookie.RefererCookieName, Value: tc.value})
				rr := requests.NewRequest()
				rr.Upstream.BasePath = "/auth"
				w := httptest.NewRecorder()

				if err := p.handleHTTPPortalScreen(t.Context(), w, r, rr, &user.User{}); err != nil {
					t.Fatal(err)
				}
				if w.Code != tc.code {
					t.Fatalf("unexpected status: got %d, want %d", w.Code, tc.code)
				}
				assertSingleRefererDeletion(t, w.Header(), p.cookie, rr.Upstream.BasePath)
			})
		}
	})

	t.Run("access grant", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			value string
		}{
			{"trusted", "https://app.example.test/dashboard"},
			{"untrusted", "https://untrusted.example.test/dashboard"},
			{"malformed", "%"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p, err := buildGrantAccessPortal([]*redirects.RedirectURIMatchConfig{trusted})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.sessions.Stop)
				r := httptest.NewRequest(http.MethodPost, "https://login.example.test/auth/login", nil)
				r.AddCookie(&http.Cookie{Name: p.cookie.RefererCookieName, Value: tc.value})
				rr := requests.NewRequest()
				rr.Upstream.BasePath = "/auth"
				rr.Upstream.BaseURL = "https://login.example.test"
				rr.Upstream.SessionID = "test-session"
				usr := newRefererCleanupUser(t)
				if err := p.keystore.SignToken(nil, nil, usr); err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()

				if err := p.grantAccess(t.Context(), w, r, rr, usr); err != nil {
					t.Fatal(err)
				}
				assertSingleRefererDeletion(t, w.Header(), p.cookie, rr.Upstream.BasePath)
			})
		}
	})
}

func newRefererCleanupPortal(t *testing.T, trusted *redirects.RedirectURIMatchConfig) *Portal {
	t.Helper()
	factory, err := cookie.NewFactory(&cookie.Config{
		RefererCookieName: "__Secure-RETURN",
		Lifetime:          300,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &Portal{
		config: &PortalConfig{
			Name:                           "referer-cleanup",
			UI:                             &ui.Parameters{},
			TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted},
		},
		logger: zap.NewNop(),
		cookie: factory,
		ui:     ui.NewFactory(),
	}
	if err := p.configureUserInterface(); err != nil {
		t.Fatal(err)
	}
	return p
}

func newRefererCleanupUser(t *testing.T) *user.User {
	t.Helper()
	usr, err := user.NewUser(map[string]any{
		"sub":   "testuser",
		"roles": []string{"user"},
		"exp":   float64(9999999999),
		"iat":   float64(1000000000),
		"nbf":   float64(1000000000),
	})
	if err != nil {
		t.Fatal(err)
	}
	return usr
}

func assertSingleRefererDeletion(t *testing.T, header http.Header, factory *cookie.Factory, basePath string) {
	t.Helper()
	issued, err := http.ParseSetCookie(factory.GetRefererCookie(basePath, "synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	var deleted []*http.Cookie
	for _, raw := range header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(raw)
		if err != nil {
			t.Fatalf("invalid Set-Cookie header: %v", err)
		}
		if c.Name == factory.RefererCookieName {
			deleted = append(deleted, c)
		}
	}
	if len(deleted) != 1 {
		t.Fatalf("got %d referer deletion headers, want exactly one", len(deleted))
	}
	got := deleted[0]
	if got.Name != issued.Name || got.Domain != issued.Domain || got.Path != issued.Path || got.Secure != issued.Secure || got.HttpOnly != issued.HttpOnly || got.SameSite != issued.SameSite {
		t.Fatal("referer deletion changed issuance name, scope, or security attributes")
	}
	if got.Value == issued.Value || got.MaxAge != -1 || !got.Expires.Equal(time.Unix(0, 0)) {
		t.Fatal("referer deletion retained a live cookie")
	}
}
