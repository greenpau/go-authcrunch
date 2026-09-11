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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// refreshIdentityStore is optional: unsupported backends cannot mint families.
type refreshIdentityStore interface {
	WithRefreshIdentity(context.Context, requests.AuthenticationEvidence, func(identity.RefreshIdentity) error) error
}

type portalRefreshAdapter struct{ portal *Portal }

type refreshRequestContextKey struct{}

func (p *Portal) configureRefresh() error {
	c := p.config.RefreshTokens
	if c == nil || !c.Enabled {
		return nil
	}
	for _, realm := range c.Realms {
		matches := 0
		for _, candidate := range p.identityStores {
			if candidate.GetRealm() == realm {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("refresh realm %q must identify exactly one store", realm)
		}
		store := p.getIdentityStoreByRealm(realm)
		if _, ok := store.(refreshIdentityStore); !ok {
			return fmt.Errorf("realm %q does not support refresh identity verification", realm)
		}
		if p.getIdentityProviderByRealm(realm) != nil {
			return fmt.Errorf("ambiguous refresh realm %q", realm)
		}
	}
	for _, name := range []string{p.cookie.AccessTokenCookieName, p.cookie.SessionIDCookieName, p.cookie.SandboxIDCookieName, p.cookie.IdentityTokenCookieName, p.cookie.RefererCookieName, p.cookie.RefreshTokenCookieName} {
		if c.CookieName == name {
			return fmt.Errorf("refresh cookie collides with an existing portal cookie")
		}
	}
	accessCookie, err := http.ParseSetCookie(p.cookie.GetAccessTokenCookie(strings.TrimPrefix(c.PublicOrigin, "https://"), "test"))
	if err != nil {
		return fmt.Errorf("invalid refresh access cookie configuration: %w", err)
	}
	accessCookie.Secure, accessCookie.HttpOnly = true, true
	if err := accessCookie.Valid(); err != nil {
		return fmt.Errorf("invalid refresh access cookie configuration: %w", err)
	}
	if strings.HasPrefix(accessCookie.Name, "__Host-") && (accessCookie.Path != "/" || accessCookie.Domain != "") {
		return fmt.Errorf("__Host- access cookies require root path and no domain")
	}
	store, err := refresh.NewMemoryStore(c.MaxSessions, c.MaxRotations)
	if err != nil {
		return err
	}
	p.refreshStore = store
	adapter := &portalRefreshAdapter{portal: p}
	policy := refresh.Policy{
		AccessLifetime:  time.Duration(min(c.AccessLifetimeSeconds, p.keystore.GetTokenLifetime(nil, nil))) * time.Second,
		IdleTimeout:     time.Duration(c.IdleTimeoutSeconds) * time.Second,
		AbsoluteTimeout: time.Duration(c.AbsoluteTimeoutSeconds) * time.Second,
	}
	p.refresh, err = refresh.NewManager(store, adapter, adapter, policy, refresh.Binding{Portal: p.config.Name, Origin: c.PublicOrigin, BasePath: c.BasePath})
	return err
}

func (p *Portal) refreshRealm(realm string) bool {
	if p.refresh == nil {
		return false
	}
	for _, allowed := range p.config.RefreshTokens.Realms {
		if realm == allowed {
			return true
		}
	}
	return false
}

func (a *portalRefreshAdapter) Sign(ctx context.Context, claims map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	u, err := user.NewUser(claims)
	if err != nil {
		return "", err
	}
	if links, ok := claims["frontend_links"]; ok {
		if err := u.AddFrontendLinks(links); err != nil {
			return "", err
		}
	}
	if err := a.portal.keystore.SignToken(nil, nil, u); err != nil {
		return "", err
	}
	// Return the same canonical representation that the real KMS signed.
	for k := range claims {
		delete(claims, k)
	}
	for k, v := range u.AsMap() {
		claims[k] = v
	}
	return u.Token, nil
}

func (a *portalRefreshAdapter) WithIdentity(ctx context.Context, principal refresh.Principal, apply func(map[string]any) error) error {
	p := a.portal
	store := p.getIdentityStoreByRealm(principal.Realm)
	backend, ok := store.(refreshIdentityStore)
	if !ok || store.GetName() != principal.Backend || !p.refreshRealm(principal.Realm) {
		return refresh.ErrDenied
	}
	proof := requests.AuthenticationEvidence{UserID: principal.UserID, CredentialVersion: principal.CredentialVersion, BackendVersion: principal.BackendVersion}
	err := backend.WithRefreshIdentity(ctx, proof, func(current identity.RefreshIdentity) error {
		if current.Username != principal.Subject {
			return refresh.ErrDenied
		}
		rr := requests.NewRequest()
		rr.Upstream.Realm = principal.Realm
		claims := map[string]any{"sub": current.Username, "email": current.Email, "name": current.Name, "roles": current.Roles, "origin": principal.Realm}
		if r, ok := ctx.Value(refreshRequestContextKey{}).(*http.Request); ok {
			claims["addr"] = addrutil.GetSourceAddress(r)
		}
		// Always transform fresh backend attributes, once per issuance.
		if err := p.transformUser(ctx, rr, claims); err != nil {
			if rr.Response.Code == 403 {
				return refresh.ErrDenied
			}
			return err
		}
		injectPortalRoles(claims, p.config)
		candidate := &user.User{}
		if err := p.injectUserChallenges(candidate, claims, current.Challenges); err != nil {
			return refresh.ErrDenied
		}
		for _, challenge := range candidate.Checkpoints {
			if !satisfiedRefreshChallenge(challenge, principal.Challenges) {
				return refresh.ErrDenied
			}
		}
		return apply(claims)
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		return refresh.ErrDenied
	}
	return err
}

func satisfiedRefreshChallenge(required *user.Checkpoint, completed []string) bool {
	for _, got := range completed {
		if got == required.Type+":"+required.Parameters {
			return true
		}
		if required.Type == "mfa" && (got == "totp:" || got == "u2f:") {
			return true
		}
	}
	return false
}
