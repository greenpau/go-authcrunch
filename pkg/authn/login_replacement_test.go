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
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

type unavailableRevocationStore struct{ tokenrefresh.Store }

func (s *unavailableRevocationStore) Revoke(context.Context, [32]byte, tokenrefresh.Binding) error {
	return fmt.Errorf("injected storage outage")
}

func (s *unavailableRevocationStore) CreateReplacing(context.Context, tokenrefresh.Session, int64, [][32]byte) error {
	return fmt.Errorf("injected storage outage: %w", tokenrefresh.ErrUnavailable)
}

func TestJSONReplacementRevocationFailure(t *testing.T) {
	for _, selected := range []bool{false, true} {
		for _, provider := range []bool{false, true} {
			t.Run(fmt.Sprintf("refresh realm=%t/oidc=%t", selected, provider), func(t *testing.T) {
				f := newRefreshPortal(t, true, false)
				p := f.portal
				if provider {
					cfg := oidcTestConfig()
					cfg.Clients[0].SkipConsent = true
					if err := cfg.Validate(); err != nil {
						t.Fatal(err)
					}
					p.config.OIDCProvider = cfg
					if err := p.configureOIDC(); err != nil {
						t.Fatal(err)
					}
				}
				first := f.login(t, "cookie")
				decodeAuth(t, first)
				oldRefresh := responseCookie(t, first, p.cookie.RefreshTokenCookieName)
				cookies := []*http.Cookie{oldRefresh}
				var oldOIDC *http.Cookie
				if provider {
					oldOIDC = responseCookie(t, first, p.cookie.OIDCSessionIDCookieName)
					cookies = append(cookies, oldOIDC)
				}
				start := f.begin(t, "cookie")
				cfg := p.config.RefreshTokens
				adapter := &portalRefreshAdapter{portal: p}
				manager, err := tokenrefresh.NewManager(&unavailableRevocationStore{p.refreshStore}, adapter, adapter,
					tokenrefresh.Policy{AccessLifetime: time.Duration(cfg.AccessLifetimeSeconds) * time.Second, IdleTimeout: time.Duration(cfg.IdleTimeoutSeconds) * time.Second, AbsoluteTimeout: time.Duration(cfg.AbsoluteTimeoutSeconds) * time.Second},
					tokenrefresh.Binding{Portal: p.config.Name, Origin: cfg.PublicOrigin, BasePath: cfg.BasePath})
				if err != nil {
					t.Fatal(err)
				}
				p.refresh = manager
				if !selected {
					// Select the access-only completion branch in this unit test.
					// The external TLS suite uses two independently configured realms.
					cfg.Realms = nil
				}
				body, err := json.Marshal(apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", SandboxID: start.SandboxID, SandboxSecret: start.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1})
				if err != nil {
					t.Fatal(err)
				}
				failed := f.request(t, http.MethodPost, "/auth/login", string(body), true, cookies...)
				if failed.Code != http.StatusServiceUnavailable {
					t.Fatalf("failed revocation returned HTTP %d", failed.Code)
				}
				var response apiauth.AuthResponse
				if json.Unmarshal(failed.Body.Bytes(), &response) != nil || response.Authenticated || response.AccessToken != "" || response.RefreshToken != "" {
					t.Fatal("failed replacement returned success or credentials")
				}
				for _, c := range failed.Result().Cookies() {
					if c.Name == p.cookie.AccessTokenCookieName || c.Name == p.cookie.RefreshTokenCookieName || c.Name == p.cookie.OIDCSessionIDCookieName {
						t.Fatal("failed revocation modified authentication cookies")
					}
				}
				if provider {
					// OIDC completion must not run before refresh revocation succeeds.
					oidcUnitCode(t, oidcUnitAuthorize(t, f, oldOIDC))
				}
				if selected {
					decodeAuth(t, f.request(t, http.MethodPost, "/auth/api/refresh_token", "{}", true, oldRefresh))
				}
			})
		}
	}
}
