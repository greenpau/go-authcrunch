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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

func (p *Portal) refreshProviderMode(realm string) string {
	if p.config.RefreshTokens == nil || !p.config.RefreshTokens.Enabled {
		return ""
	}
	for _, config := range p.config.RefreshTokens.ProviderRevalidation {
		if config.Realm == realm {
			return config.Mode
		}
	}
	return ""
}

// Only a successfully redeemed upstream callback enters this issuer. Neither
// access JWTs nor cross-device claim transfers are authentication for this path.
func (p *Portal) issueProviderRefresh(ctx context.Context, r *http.Request, rr *requests.Request) (*user.User, *tokenrefresh.Result, error) {
	provider := p.getIdentityProviderByRealm(rr.Upstream.Realm)
	if provider == nil || provider.GetKind() != "oauth" || rr.Upstream.Method != "oauth2" || rr.Response.Code != http.StatusOK || !rr.Response.ReturnURLBound {
		return nil, nil, tokenrefresh.ErrDenied
	}
	if err := p.validateProviderRefreshLogin(r); err != nil {
		rr.Response.Code = http.StatusForbidden
		return nil, nil, err
	}
	claims, ok := rr.Response.Payload.(map[string]any)
	if !ok {
		return nil, nil, tokenrefresh.ErrDenied
	}
	snapshot, err := encodeProviderSnapshot(claims)
	if err != nil {
		return nil, nil, err
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return nil, nil, tokenrefresh.ErrDenied
	}
	providerBinding, err := providerSnapshotBinding(provider)
	if err != nil {
		return nil, nil, tokenrefresh.ErrUnavailable
	}
	principal := tokenrefresh.Principal{
		ExternalIdentity: rr.ExternalIdentity,
		Source:           tokenrefresh.ProviderSnapshotSource, Backend: provider.GetName(), BackendKind: provider.GetKind(),
		Realm: provider.GetRealm(), Subject: subject, UserID: subject, BackendVersion: providerBinding,
		AuthTime: time.Now().Unix(), Methods: []string{"federated"}, ProviderSnapshot: snapshot,
	}
	var previous []string
	for _, cookie := range r.CookiesNamed(p.cookie.RefreshTokenCookieName) {
		previous = append(previous, cookie.Value)
	}
	refreshContext := context.WithValue(ctx, refreshRequestContextKey{}, r)
	tokens, err := p.refresh.IssueReplacing(refreshContext, principal, tokenrefresh.CookieTransport, previous)
	if err != nil {
		return nil, nil, err
	}
	u, err := p.userFromProviderRefresh(refreshContext, tokens)
	return u, tokens, err
}

// A verified, browser-bound OAuth callback is a cross-site navigation. The
// ordinary same-origin form-login Fetch Metadata rule cannot apply to it.
func (p *Portal) validateProviderRefreshLogin(r *http.Request) error {
	if err := p.validateRefreshOrigin(r); err != nil {
		return err
	}
	if r.Method != http.MethodGet {
		return tokenrefresh.ErrDenied
	}
	if values := r.Header.Values("Origin"); len(values) > 1 || len(values) == 1 && values[0] != p.config.RefreshTokens.PublicOrigin {
		return tokenrefresh.ErrDenied
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return tokenrefresh.ErrDenied
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" {
		return tokenrefresh.ErrDenied
	}
	return nil
}

// Bind evidence to normalized provider trust settings as well as its identity.
// Persist only the digest; configuration can include confidential credentials.
func providerSnapshotBinding(provider idp.IdentityProvider) (string, error) {
	return state.Binding(map[string]any{"config": provider.GetConfig(), "driver": provider.GetDriver()})
}

func (p *Portal) refreshProviderClaimsCurrent(ctx context.Context, principal tokenrefresh.Principal, current *identity.RefreshIdentity) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider := p.getIdentityProviderByRealm(principal.Realm)
	if !p.refreshRealm(principal.Realm) || p.refreshProviderMode(principal.Realm) != TokenRefreshProviderSnapshot || provider == nil || !provider.Configured() || provider.GetName() != principal.Backend || provider.GetKind() != principal.BackendKind || principal.BackendKind != "oauth" || principal.Source != tokenrefresh.ProviderSnapshotSource || principal.UserID != principal.Subject || principal.CredentialVersion != 0 || !slices.Contains(principal.Methods, "federated") {
		return nil, tokenrefresh.ErrDenied
	}
	providerBinding, err := providerSnapshotBinding(provider)
	if err != nil {
		return nil, tokenrefresh.ErrUnavailable
	}
	if principal.BackendVersion != providerBinding {
		return nil, tokenrefresh.ErrDenied
	}
	claims, err := decodeProviderSnapshot(principal.ProviderSnapshot)
	if err != nil || claims["sub"] != principal.Subject {
		return nil, tokenrefresh.ErrDenied
	}
	combineProviderRoles(claims)
	claims["origin"], claims["realm"] = principal.Realm, principal.Realm
	if r, ok := ctx.Value(refreshRequestContextKey{}).(*http.Request); ok {
		claims["addr"] = addrutil.GetSourceAddress(r)
		claims["iss"] = util.GetIssuerURL(r)
	}
	rr := requests.NewRequest()
	rr.Upstream.Realm, rr.Upstream.Method = principal.Realm, "oauth2"
	if current != nil {
		rr.User.AuthMethods = append([]string(nil), current.AuthMethods...)
		rr.User.Challenges = append([]string(nil), current.Challenges...)
		rr.User.AuthChallengePolicy = current.AuthChallengePolicy
		if !rr.User.AuthChallengePolicy {
			rr.User.Challenges = slices.DeleteFunc(rr.User.Challenges, func(c string) bool { return c == "password" })
		}
		if len(rr.User.Challenges) > 0 {
			rr.User.AuthChallengePolicy = true
		}
		if len(current.Roles) > 0 {
			mergeProviderRoles(claims, current.Roles)
		}
	}
	if err := p.transformUser(ctx, rr, claims); err != nil {
		if rr.Response.Code == http.StatusForbidden {
			return nil, tokenrefresh.ErrDenied
		}
		return nil, err
	}
	// Provider AMR/ACR cannot satisfy local factor requirements. Explicit
	// challenge policies must be satisfied by a separate supported login flow.
	if current == nil {
		if len(principal.Challenges) != 0 || len(principal.Methods) != 1 {
			return nil, tokenrefresh.ErrDenied
		}
		if err := p.checkDirectAuthenticationPolicy(rr, claims, nil); err != nil {
			return nil, tokenrefresh.ErrDenied
		}
	} else if len(rr.User.Challenges) > 0 || claims["challenges"] != nil {
		candidate := &user.User{}
		if err := p.injectUserChallenges(candidate, claims, rr.User.Challenges); err != nil {
			return nil, tokenrefresh.ErrDenied
		}
		for _, required := range candidate.Checkpoints {
			if !satisfiedRefreshChallenge(required, principal.Challenges) {
				return nil, tokenrefresh.ErrDenied
			}
		}
	}
	if current != nil {
		claims["id"] = principal.ExternalIdentity.Evidence.UserID
	}
	// The current roles are authoritative. User canonicalization also consumes
	// these legacy nested carriers, which must not restore roles after policy.
	delete(claims, "realm_access")
	delete(claims, "app_metadata")
	injectPortalRoles(claims, p.config)
	return claims, nil
}

func (p *Portal) userFromProviderRefresh(ctx context.Context, tokens *tokenrefresh.Result) (*user.User, error) {
	claims, err := p.refreshProviderClaims(ctx, tokens.Principal)
	if err != nil {
		return nil, err
	}
	u, err := user.NewUser(tokens.Claims)
	if err != nil {
		return nil, err
	}
	u.Token, u.TokenName, u.Authorized = tokens.AccessToken, p.cookie.AccessTokenCookieName, true
	u.Authenticator = user.Authenticator{Name: tokens.Principal.Backend, Realm: tokens.Principal.Realm, Method: tokens.Principal.BackendKind}
	// Keep provider proof separate from local password/profile authority.
	u.ExternalIdentity = tokens.Principal.ExternalIdentity
	u.LoginMethods = append([]string(nil), tokens.Principal.Methods...)
	if links, exists := claims["frontend_links"]; exists {
		if err := u.AddFrontendLinks(links); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// Snapshot documents have bounded depth, node count and encoded size. Preserve
// arbitrary verified JSON claims (including exact numbers) needed by transforms,
// while removing protocol credentials and portal-owned proof/session fields.
func encodeProviderSnapshot(claims map[string]any) ([]byte, error) {
	limits := providerSnapshotLimits{nodes: 4096, bytes: tokenrefresh.MaxProviderSnapshotSize}
	clean, err := cleanProviderValue(claims, 0, &limits)
	if err != nil {
		return nil, tokenrefresh.ErrDenied
	}
	m := clean.(map[string]any)
	// Preserve the recognized role contribution before recursively stripping
	// authorization credentials. The rest of this container is never proof.
	if metadata, ok := claims["app_metadata"].(map[string]any); ok {
		if authorization, ok := metadata["authorization"].(map[string]any); ok {
			if roles, exists := authorization["roles"]; exists {
				roles, err := cleanProviderValue(roles, 3, &limits)
				if err != nil {
					return nil, tokenrefresh.ErrDenied
				}
				mergeProviderRoles(m, roles)
			}
		}
	}
	for _, key := range []string{"iss", "aud", "scope", "scopes", "iat", "nbf", "exp", "jti", "sid", "auth_time", "amr", "acr", "origin", "realm", "addr", "challenges", "frontend_links", "nonce", "state"} {
		delete(m, key)
	}
	sub, ok := m["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" || len(sub) > 4096 {
		return nil, tokenrefresh.ErrDenied
	}
	data, err := json.Marshal(m)
	if err != nil || len(data) > tokenrefresh.MaxProviderSnapshotSize {
		return nil, tokenrefresh.ErrDenied
	}
	return data, nil
}

func mergeProviderRoles(claims map[string]any, roles any) {
	combined := map[string]any{"roles": claims["roles"], "role": roles}
	combineGroupRoles(combined)
	if normalized, exists := combined["roles"]; exists {
		claims["roles"] = normalized
	}
}

func combineProviderRoles(claims map[string]any) {
	combineGroupRoles(claims)
	if access, ok := claims["realm_access"].(map[string]any); ok {
		mergeProviderRoles(claims, access["roles"])
	}
}

func decodeProviderSnapshot(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > tokenrefresh.MaxProviderSnapshotSize {
		return nil, tokenrefresh.ErrDenied
	}
	var claims map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil || claims == nil {
		return nil, tokenrefresh.ErrDenied
	}
	canonical, err := encodeProviderSnapshot(claims)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, tokenrefresh.ErrDenied
	}
	return claims, nil
}

// Bound work and intermediate allocations before constructing a canonical copy.
type providerSnapshotLimits struct{ nodes, bytes int }

func cleanProviderValue(value any, depth int, limits *providerSnapshotLimits) (any, error) {
	limits.nodes--
	if depth > 16 || limits.nodes < 0 {
		return nil, tokenrefresh.ErrDenied
	}
	switch v := value.(type) {
	case map[string]any:
		if len(v) > limits.nodes {
			return nil, tokenrefresh.ErrDenied
		}
		out := make(map[string]any, len(v))
		for key, child := range v {
			if !utf8.ValidString(key) || len(key) > tokenrefresh.MaxProviderSnapshotSize {
				return nil, tokenrefresh.ErrDenied
			}
			switch strings.ToLower(key) {
			case "access_token", "refresh_token", "id_token", "client_secret", "password", "code", "code_verifier", "client_assertion", "authorization", "token":
				continue
			}
			limits.bytes -= len(key)
			if limits.bytes < 0 {
				return nil, tokenrefresh.ErrDenied
			}
			clean, err := cleanProviderValue(child, depth+1, limits)
			if err != nil {
				return nil, err
			}
			out[key] = clean
		}
		return out, nil
	case []any:
		if len(v) > limits.nodes {
			return nil, tokenrefresh.ErrDenied
		}
		out := make([]any, len(v))
		for i, child := range v {
			clean, err := cleanProviderValue(child, depth+1, limits)
			if err != nil {
				return nil, err
			}
			out[i] = clean
		}
		return out, nil
	case []string:
		if len(v) > limits.nodes {
			return nil, tokenrefresh.ErrDenied
		}
		out := make([]any, len(v))
		for i, child := range v {
			clean, err := cleanProviderValue(child, depth+1, limits)
			if err != nil {
				return nil, err
			}
			out[i] = clean
		}
		return out, nil
	case string:
		limits.bytes -= len(v)
		if !utf8.ValidString(v) || limits.bytes < 0 {
			return nil, tokenrefresh.ErrDenied
		}
		return v, nil
	case json.Number:
		limits.bytes -= len(v)
		if limits.bytes < 0 {
			return nil, tokenrefresh.ErrDenied
		}
		return v, nil
	case nil, bool, float64, float32, int, int64, int32, uint, uint64, uint32:
		return v, nil
	default:
		return nil, tokenrefresh.ErrDenied
	}
}

// Provider issuance uses the same staged family replacement and bounded cleanup
// as local completion. A later delivery failure never leaves an unseen live grant.
func (p *Portal) authorizeProviderRefresh(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) (err error) {
	headers := w.Header().Clone()
	u, tokens, err := p.issueProviderRefresh(ctx, r, rr)
	granted := false
	defer func() {
		if err == nil {
			return
		}
		if tokens != nil {
			err = errors.Join(err, p.discardUndeliveredRefresh(ctx, tokens, tokenrefresh.CookieTransport))
		}
		if granted {
			err = errors.Join(err, p.sessions.Delete(u.Claims.ID))
		}
		clear(w.Header())
		maps.Copy(w.Header(), headers)
		rr.Response.Authenticated = false
		status := http.StatusServiceUnavailable
		if errors.Is(err, tokenrefresh.ErrDenied) && !errors.Is(err, tokenrefresh.ErrUnavailable) {
			status = http.StatusUnauthorized
			if rr.Response.Code == http.StatusForbidden {
				status = http.StatusForbidden
			}
		}
		rr.Response.Code = status
	}()
	if err != nil {
		return err
	}
	if err = p.grantAccess(ctx, w, r, rr, u); err != nil {
		return err
	}
	granted = true
	p.deliverRefreshCookies(w, r, tokens)
	// Provider cross-device transfers remain access-only. The approving browser
	// records this actual family so logout/replay still invalidate its approvals.
	if p.crossDevice != nil && p.crossDeviceBinding(r) != "" {
		p.completeCrossDeviceLogin(w, r, rr, u, u, tokens.Principal.ProviderSnapshot, tokens)
	}
	return nil
}

func (p *Portal) withProviderRefreshClaims(ctx context.Context, principal tokenrefresh.Principal, apply func(map[string]any) error) error {
	provider := p.getIdentityProviderByRealm(principal.Realm)
	if principal.ExternalIdentity.Evidence.UserID == "" {
		// Legacy injected test/embedding providers have no attachment capability.
		// Built-in providers must never renew a pre-attachment family.
		if _, ok := provider.(interface{ IdentityAttachment() *attachment.Attachment }); ok {
			return tokenrefresh.ErrDenied
		}
		claims, err := p.refreshProviderClaimsCurrent(ctx, principal, nil)
		if err != nil {
			return err
		}
		if err := p.validateAccessAudience(claims); err != nil {
			return err
		}
		return apply(claims)
	}
	a, realm, err := p.externalIdentityAttachment(principal.ExternalIdentity)
	if err != nil || realm != principal.Realm {
		return tokenrefresh.ErrDenied
	}
	store, err := a.Store()
	if err != nil {
		return tokenrefresh.ErrUnavailable
	}
	err = store.WithRefreshIdentity(ctx, principal.ExternalIdentity.Evidence, func(current identity.RefreshIdentity) error {
		claims, err := p.refreshProviderClaimsCurrent(ctx, principal, &current)
		if err != nil {
			return err
		}
		if err := p.validateAccessAudience(claims); err != nil {
			return err
		}
		return apply(claims)
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		return tokenrefresh.ErrDenied
	}
	return err
}

func (p *Portal) refreshProviderClaims(ctx context.Context, principal tokenrefresh.Principal) (map[string]any, error) {
	var claims map[string]any
	err := p.withProviderRefreshClaims(ctx, principal, func(current map[string]any) error { claims = current; return nil })
	return claims, err
}
