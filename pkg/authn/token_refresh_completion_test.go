// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type canceledOIDCCompletion struct {
	oidc.OpenIDProvider
	cancel context.CancelFunc
}

func (p *canceledOIDCCompletion) CompleteLogin(context.Context, http.ResponseWriter, *http.Request, oidc.Authentication) error {
	p.cancel()
	return context.Canceled
}

type failedDiscardStore struct {
	tokenrefresh.Store
	revoked    bool
	contextErr error
	bounded    bool
}

func (s *failedDiscardStore) Revoke(ctx context.Context, _ [32]byte, _ tokenrefresh.Binding) error {
	s.revoked = true
	s.contextErr = ctx.Err()
	_, s.bounded = ctx.Deadline()
	return fmt.Errorf("injected discard outage")
}

func TestTokenRefreshJSONCompletionDiscard(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup unavailable=%t", unavailable), func(t *testing.T) {
			f := newRefreshPortal(t, true, false)
			p := f.portal
			p.refreshStore.Close()
			p.config.RefreshTokens.MaxSessions = 1
			if err := p.configureRefresh(); err != nil {
				t.Fatal(err)
			}
			var outage *failedDiscardStore
			if unavailable {
				outage = &failedDiscardStore{Store: p.refreshStore}
				adapter := &portalRefreshAdapter{portal: p}
				cfg := p.config.RefreshTokens
				var err error
				p.refresh, err = tokenrefresh.NewManager(outage, adapter, adapter, tokenrefresh.Policy{AccessLifetime: time.Duration(cfg.AccessLifetimeSeconds) * time.Second, IdleTimeout: time.Duration(cfg.IdleTimeoutSeconds) * time.Second, AbsoluteTimeout: time.Duration(cfg.AbsoluteTimeoutSeconds) * time.Second}, tokenrefresh.Binding{Portal: p.config.Name, Origin: cfg.PublicOrigin, BasePath: cfg.BasePath})
				if err != nil {
					t.Fatal(err)
				}
			}
			start := f.begin(t, "cookie")
			p.config.OIDCProvider = oidcTestConfig()
			if err := p.configureOIDC(); err != nil {
				t.Fatal(err)
			}
			provider := p.oidc
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p.oidc = &canceledOIDCCompletion{OpenIDProvider: provider, cancel: cancel}
			t.Cleanup(func() { p.oidc = provider })
			body, err := json.Marshal(apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", RefreshTransport: "cookie", SandboxID: start.SandboxID, SandboxSecret: start.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/login", strings.NewReader(string(body))).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Origin", refreshTestOrigin)
			w := httptest.NewRecorder()
			if err := p.ServeHTTP(ctx, w, r, requests.NewRequest()); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusServiceUnavailable || ctx.Err() != context.Canceled {
				t.Fatalf("failed completion returned %d", w.Code)
			}
			for _, c := range w.Result().Cookies() {
				if (c.Name == p.cookie.AccessTokenCookieName || c.Name == p.cookie.RefreshTokenCookieName || c.Name == p.cookie.OIDCSessionIDCookieName) && c.MaxAge >= 0 && c.Value != "" && (c.Expires.IsZero() || c.Expires.After(time.Now())) {
					t.Fatal("failed completion delivered a credential")
				}
			}
			if unavailable {
				if !outage.revoked || outage.contextErr != nil || !outage.bounded {
					t.Fatal("cleanup did not use an independent bounded context")
				}
				return
			}
			p.oidc = provider
			decodeAuth(t, f.login(t, "cookie"))
		})
	}
}

func TestTokenRefreshJSONOIDCCapacityRecovery(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	p.refreshStore.Close()
	p.config.RefreshTokens.MaxSessions = 1
	if err := p.configureRefresh(); err != nil {
		t.Fatal(err)
	}
	cfg := oidcTestConfig()
	cfg.MaxSessions = 1
	p.config.OIDCProvider = cfg
	if err := p.configureOIDC(); err != nil {
		t.Fatal(err)
	}
	first := f.login(t, "cookie")
	decodeAuth(t, first)
	old := responseCookie(t, first, p.cookie.RefreshTokenCookieName)
	oc := responseCookie(t, first, p.cookie.OIDCSessionIDCookieName)
	if err := p.refresh.Logout(t.Context(), old.Value, tokenrefresh.CookieTransport); err != nil {
		t.Fatal(err)
	}
	failed := f.login(t, "cookie")
	if failed.Code == http.StatusOK {
		t.Fatal("OIDC capacity did not reject login")
	}
	r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/logout", nil)
	r.AddCookie(oc)
	p.oidc.Logout(httptest.NewRecorder(), r)
	retry := f.login(t, "cookie")
	if retry.Code != http.StatusOK {
		t.Fatalf("login after capacity recovery returned %d", retry.Code)
	}
}

func TestTokenRefreshJSONSessionCacheCapacityRecovery(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	p.refreshStore.Close()
	p.config.RefreshTokens.MaxSessions = 1
	if err := p.configureRefresh(); err != nil {
		t.Fatal(err)
	}
	p.config.OIDCProvider = oidcTestConfig()
	if err := p.configureOIDC(); err != nil {
		t.Fatal(err)
	}
	preloadID := preloadSessionCacheNearCapacity(t, p)
	failed := f.login(t, "cookie")
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache capacity refusal returned %d, want %d", failed.Code, http.StatusServiceUnavailable)
	}
	for _, cookie := range failed.Result().Cookies() {
		if (cookie.Name == p.cookie.AccessTokenCookieName || cookie.Name == p.cookie.RefreshTokenCookieName || cookie.Name == p.cookie.OIDCSessionIDCookieName) && cookie.Value != "" {
			t.Fatalf("cache capacity refusal delivered credential cookie %q", cookie.Name)
		}
	}
	if failed.Header().Get("Authorization") != "" || failed.Header().Get("Location") != "" {
		t.Fatal("cache capacity refusal delivered credential headers")
	}
	if err := p.sessions.Delete(preloadID); err != nil {
		t.Fatal(err)
	}
	retry := f.login(t, "cookie")
	if retry.Code != http.StatusOK {
		t.Fatalf("healthy retry returned %d", retry.Code)
	}
}
