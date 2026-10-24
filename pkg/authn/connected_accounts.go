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
	"fmt"
	"net/http"
	"slices"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

func (p *Portal) externalIdentityAttachment(proof requests.ExternalIdentity) (*attachment.Attachment, string, error) {
	for _, provider := range p.identityProviders {
		if provider.GetName() == proof.Provider && provider.GetKind() == proof.Kind {
			return p.providerIdentityAttachment(provider), provider.GetRealm(), nil
		}
	}
	for _, store := range p.identityStores {
		if store.GetName() == proof.Provider && store.GetKind() == proof.Kind {
			if consumer, ok := store.(attachment.Consumer); ok {
				return consumer.IdentityAttachment(), store.GetRealm(), nil
			}
		}
	}
	return nil, "", identity.ErrExternalAccountDenied
}

// External login keeps the upstream subject/claims for policy compatibility and
// adds the immutable local ID. Local roles and factor requirements are read
// within the same transaction that authorizes signing.
func (p *Portal) externalAccountClaims(ctx context.Context, r *http.Request, rr *requests.Request, raw map[string]any, current identity.RefreshIdentity) (map[string]any, []*user.Checkpoint, error) {
	claims, err := cloneExternalClaims(raw)
	if err != nil {
		return nil, nil, err
	}
	combineProviderRoles(claims)
	if len(current.Roles) > 0 {
		roles, _ := claims["roles"].([]string)
		claims["roles"] = append(roles, current.Roles...)
	}
	claims["iss"], claims["addr"] = util.GetIssuerURL(r), addrutil.GetSourceAddress(r)
	claims["origin"], claims["realm"] = rr.Upstream.Realm, rr.Upstream.Realm
	applyExternalAccountPolicy(rr, current)
	if err := p.transformUser(ctx, rr, claims); err != nil {
		return nil, nil, err
	}
	var checkpoints []*user.Checkpoint
	if len(rr.User.Challenges) > 0 || claims["challenges"] != nil {
		candidate := &user.User{}
		if err := p.injectUserChallenges(candidate, claims, rr.User.Challenges); err != nil {
			return nil, nil, err
		}
		checkpoints = candidate.Checkpoints
	}
	now := time.Now().Unix()
	claims["id"] = rr.ExternalIdentity.Evidence.UserID
	claims["jti"], claims["iat"], claims["nbf"], claims["exp"] = rr.Upstream.SessionID, now, now-60, now+int64(p.accessLifetimeSeconds())
	claims["iss"], claims["addr"] = util.GetIssuerURL(r), addrutil.GetSourceAddress(r)
	claims["origin"], claims["realm"] = rr.Upstream.Realm, rr.Upstream.Realm
	delete(claims, "amr")
	delete(claims, "realm_access")
	delete(claims, "app_metadata")
	injectPortalRoles(claims, p.config)
	return claims, checkpoints, nil
}

func applyExternalAccountPolicy(rr *requests.Request, current identity.RefreshIdentity) {
	rr.User.AuthMethods = append([]string(nil), current.AuthMethods...)
	rr.User.AuthChallengePolicy = current.AuthChallengePolicy
	rr.User.Challenges = append([]string(nil), current.Challenges...)
	// An external login replaces the default local password, but never a
	// password explicitly required by the user's or administrator's policy.
	if !rr.User.AuthChallengePolicy {
		rr.User.Challenges = slices.DeleteFunc(rr.User.Challenges, func(c string) bool { return c == "password" })
	}
}

func cloneExternalClaims(raw map[string]any) (map[string]any, error) {
	encoded, err := encodeProviderSnapshot(raw)
	if err != nil {
		return nil, err
	}
	return decodeProviderSnapshot(encoded)
}

func (p *Portal) externalLoginClaims(rr *requests.Request) (map[string]any, error) {
	if rr.Upstream.Method == "ldap" {
		return map[string]any{"sub": rr.User.Username, "email": rr.User.Email, "name": rr.User.FullName, "roles": rr.User.Roles}, nil
	}
	raw, ok := rr.Response.Payload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("external login has no claims")
	}
	return raw, nil
}

func (p *Portal) authorizeConnectedLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	a, realm, err := p.externalIdentityAttachment(rr.ExternalIdentity)
	if err != nil || realm != rr.Upstream.Realm {
		rr.Response.Code = http.StatusUnauthorized
		return identity.ErrExternalAccountDenied
	}
	store, err := a.Store()
	if err != nil {
		rr.Response.Code = http.StatusServiceUnavailable
		return err
	}
	raw, err := p.externalLoginClaims(rr)
	if err != nil {
		return err
	}
	var issued *user.User
	var checkpoints []*user.Checkpoint
	var currentIdentity identity.RefreshIdentity
	err = store.WithRefreshIdentity(ctx, rr.ExternalIdentity.Evidence, func(current identity.RefreshIdentity) error {
		currentIdentity = current
		claims, required, err := p.externalAccountClaims(ctx, r, rr, raw, current)
		if err != nil {
			return err
		}
		checkpoints = required
		if len(required) > 0 {
			return nil
		}
		issued, err = p.signConnectedUser(ctx, rr, claims, []string{"federated"})
		return err
	})
	if err != nil {
		if rr.Response.Code < 400 || p.refreshProviderMode(realm) == TokenRefreshProviderSnapshot {
			rr.Response.Code = http.StatusUnauthorized
		}
		return err
	}
	if len(checkpoints) > 0 {
		return p.beginConnectedSandbox(ctx, w, r, rr, a, raw, currentIdentity, checkpoints)
	}
	// Provider renewal still uses its captured upstream-claims contract. The
	// refresh adapter independently validates the same local record/version.
	if rr.Upstream.Method == "oauth2" && p.refreshRealm(realm) && p.refreshProviderMode(realm) == TokenRefreshProviderSnapshot {
		return p.authorizeProviderRefresh(ctx, w, r, rr)
	}
	if err := p.grantAccess(ctx, w, r, rr, issued); err != nil {
		return err
	}
	if p.crossDevice != nil {
		snapshot, err := encodeProviderSnapshot(raw)
		if err != nil {
			return err
		}
		p.completeCrossDeviceLogin(w, r, rr, issued, issued, snapshot, nil)
	}
	return nil
}

func (p *Portal) signConnectedUser(ctx context.Context, rr *requests.Request, claims map[string]any, methods []string) (*user.User, error) {
	if p.managedRefreshUnavailable() {
		return nil, tokenrefresh.ErrUnavailable
	}
	claims["amr"] = append([]string(nil), methods...)
	claims["auth_time"] = rr.ExternalIdentity.Evidence.AuthenticatedAt
	claims["nonce"] = util.GetRandomString(32)
	u, err := p.newAccessUser(claims)
	if err != nil {
		return nil, err
	}
	u.ExternalIdentity = rr.ExternalIdentity
	u.Authenticator = user.Authenticator{Name: rr.ExternalIdentity.Provider, Realm: rr.Upstream.Realm, Method: rr.ExternalIdentity.Kind}
	u.LoginMethods = append([]string(nil), methods...)
	if links := claims["frontend_links"]; links != nil {
		if err := u.AddFrontendLinks(links); err != nil {
			return nil, err
		}
	}
	if err := p.signAccessUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (p *Portal) beginConnectedSandbox(_ context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, a *attachment.Attachment, raw map[string]any, current identity.RefreshIdentity, checkpoints []*user.Checkpoint) error {
	var localRealm string
	for _, backend := range p.identityStores {
		if backend.GetKind() == "local" && backend.GetName() == a.StoreName() {
			localRealm = backend.GetRealm()
		}
	}
	if localRealm == "" {
		rr.Response.Code = http.StatusForbidden
		if p.refreshProviderMode(rr.Upstream.Realm) == TokenRefreshProviderSnapshot {
			rr.Response.Code = http.StatusUnauthorized
		}
		return fmt.Errorf("local challenge realm is not enabled")
	}
	u, err := user.NewUser(map[string]any{"sub": current.Username, "email": current.Email, "roles": current.Roles})
	if err != nil {
		return err
	}
	u.ExternalClaims, err = cloneExternalClaims(raw)
	if err != nil {
		return err
	}
	u.ExternalIdentity = rr.ExternalIdentity
	u.LoginEvidence = rr.ExternalIdentity.Evidence
	u.LoginUsername, u.LoginEmail = current.Username, current.Email
	u.LoginMethods = []string{"federated"}
	u.Checkpoints = checkpoints
	u.RefreshTransport = "cookie"
	u.LoginReturnURL, u.LoginReturnURLBound = rr.Response.ReturnURL, rr.Response.ReturnURLBound
	u.Authenticator = user.Authenticator{Name: a.StoreName(), Realm: localRealm, Method: "local", NextChallenge: checkpoints[0].Type,
		TempSessionID: util.GetRandomStringFromRange(36, 48), TempSecret: util.GetRandomStringFromRange(36, 48)}
	if err := p.addBrowserSandbox(w, r, rr, u); err != nil {
		rr.Response.Code = sandboxAdmissionStatus(err)
		return err
	}
	w.Header().Set("Location", rr.Upstream.BasePath+"sandbox/"+u.Authenticator.TempSessionID)
	rr.Response.Code = http.StatusSeeOther
	return nil
}

func (p *Portal) issueConnectedSandbox(ctx context.Context, r *http.Request, rr *requests.Request, proof *user.User, maxExpiry int64) (*user.User, error) {
	a, realm, err := p.externalIdentityAttachment(proof.ExternalIdentity)
	if err != nil {
		return nil, err
	}
	store, err := a.Store()
	if err != nil {
		return nil, err
	}
	rr.ExternalIdentity = proof.ExternalIdentity
	rr.Upstream.Realm, rr.Upstream.Name, rr.Upstream.Method = realm, proof.ExternalIdentity.Provider, proof.ExternalIdentity.Kind
	if rr.Upstream.Method == "oauth" {
		rr.Upstream.Method = "oauth2"
	}
	raw := proof.ExternalClaims
	// LDAP starts in its ordinary password sandbox, before the external proof
	// exists. Preserve the verified LDAP identity, independent of transformations.
	if raw == nil && proof.ExternalIdentity.Kind == "ldap" {
		raw = map[string]any{"sub": proof.LoginUsername, "email": proof.LoginEmail, "name": rr.User.FullName, "roles": rr.User.Roles}
	}
	var result *user.User
	err = store.WithRefreshIdentity(ctx, proof.ExternalIdentity.Evidence, func(current identity.RefreshIdentity) error {
		claims, required, err := p.externalAccountClaims(ctx, r, rr, raw, current)
		if err != nil {
			return err
		}
		var completed []string
		for _, checkpoint := range proof.Checkpoints {
			if !checkpoint.Passed {
				return identity.ErrExternalAccountDenied
			}
			completed = append(completed, checkpoint.Type+":"+checkpoint.Parameters)
		}
		for _, checkpoint := range required {
			if !satisfiedRefreshChallenge(checkpoint, completed) {
				return identity.ErrExternalAccountDenied
			}
		}
		methods := append([]string{"federated"}, proof.LoginMethods...)
		methods = slices.Compact(methods)
		// Transferring a completed external login cannot extend its lifetime.
		// Apply the bound before signing, while the identity transaction is held.
		if maxExpiry != 0 {
			if maxExpiry <= time.Now().Unix() {
				return identity.ErrExternalAccountDenied
			}
			claims["exp"] = min(claims["exp"].(int64), maxExpiry)
		}
		result, err = p.signConnectedUser(ctx, rr, claims, methods)
		return err
	})
	return result, err
}

// Renewal preserves the upstream snapshot and the actual local checkpoints.
func (p *Portal) issueConnectedSandboxTokens(ctx context.Context, r *http.Request, rr *requests.Request, proof *user.User) (*user.User, *tokenrefresh.Result, error) {
	if p.managedRefreshUnavailable() {
		return nil, nil, tokenrefresh.ErrUnavailable
	}
	issued, err := p.issueConnectedSandbox(ctx, r, rr, proof, 0)
	if err != nil {
		return nil, nil, err
	}
	realm := issued.Authenticator.Realm
	if proof.ExternalIdentity.Kind != "oauth" || !p.refreshRealm(realm) || p.refreshProviderMode(realm) != TokenRefreshProviderSnapshot {
		return issued, nil, nil
	}
	if err := p.validateRefreshLogin(r, proof.RefreshTransport); err != nil {
		return nil, nil, err
	}
	provider := p.getIdentityProviderByRealm(realm)
	binding, err := providerSnapshotBinding(provider)
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := encodeProviderSnapshot(proof.ExternalClaims)
	if err != nil {
		return nil, nil, err
	}
	subject, _ := proof.ExternalClaims["sub"].(string)
	principal := tokenrefresh.Principal{Source: tokenrefresh.ProviderSnapshotSource,
		Backend: provider.GetName(), BackendKind: provider.GetKind(), Realm: realm,
		Subject: subject, UserID: subject, BackendVersion: binding,
		AuthTime: proof.ExternalIdentity.Evidence.AuthenticatedAt, Methods: issued.LoginMethods,
		ProviderSnapshot: snapshot, ExternalIdentity: proof.ExternalIdentity}
	for _, checkpoint := range proof.Checkpoints {
		if !checkpoint.Passed {
			return nil, nil, tokenrefresh.ErrDenied
		}
		principal.Challenges = append(principal.Challenges, checkpoint.Type+":"+checkpoint.Parameters)
	}
	var previous []string
	for _, c := range r.CookiesNamed(p.cookie.RefreshTokenCookieName) {
		previous = append(previous, c.Value)
	}
	refreshContext := context.WithValue(ctx, refreshRequestContextKey{}, r)
	tokens, err := p.refresh.IssueReplacing(refreshContext, principal, proof.RefreshTransport, previous)
	if err != nil {
		return nil, nil, err
	}
	issued, err = p.userFromProviderRefresh(refreshContext, tokens)
	return issued, tokens, err
}

// After the directory password is verified, any attached local requirements
// run against the local identity, with separate checkpoint evidence.
func (p *Portal) advanceConnectedLDAP(u *user.User, rr *requests.Request) error {
	a, _, err := p.externalIdentityAttachment(u.ExternalIdentity)
	if err != nil {
		return err
	}
	store, err := a.Store()
	if err != nil {
		return err
	}
	r := rr.Upstream.Request
	if r == nil {
		return identity.ErrExternalAccountDenied
	}
	return store.WithRefreshIdentity(r.Context(), u.ExternalIdentity.Evidence, func(current identity.RefreshIdentity) error {
		_, required, err := p.externalAccountClaims(r.Context(), r, rr, u.ExternalClaims, current)
		if err != nil || len(required) == 0 {
			return err
		}
		var realm string
		for _, backend := range p.identityStores {
			if backend.GetKind() == "local" && backend.GetName() == a.StoreName() {
				realm = backend.GetRealm()
			}
		}
		if realm == "" {
			return identity.ErrExternalAccountDenied
		}
		u.Authenticator.Name, u.Authenticator.Realm, u.Authenticator.Method = a.StoreName(), realm, "local"
		u.Authenticator.NextChallenge = required[0].Type
		u.LoginEvidence = u.ExternalIdentity.Evidence
		u.LoginUsername, u.LoginEmail = current.Username, current.Email
		rr.User.Username, rr.User.Email = current.Username, current.Email
		u.Checkpoints, u.LoginMethods, u.Authorized = required, []string{"federated"}, false
		return nil
	})
}

// Capability providers own bindings shared across consumers. Legacy injected
// HTTP providers receive a private portal-lifetime memory store.
func (p *Portal) providerIdentityAttachment(provider idp.IdentityProvider) *attachment.Attachment {
	if consumer, ok := provider.(attachment.Consumer); ok {
		return consumer.IdentityAttachment()
	}
	if existing, ok := p.externalAttachments.Load(provider.GetName()); ok {
		return existing.(*attachment.Attachment)
	}
	created, _ := attachment.New(attachment.Config{})
	actual, _ := p.externalAttachments.LoadOrStore(provider.GetName(), created)
	return actual.(*attachment.Attachment)
}
