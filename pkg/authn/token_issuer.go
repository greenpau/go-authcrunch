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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// issueSandboxTokens is shared by browser and JSON login after atomic redemption.
func (p *Portal) issueSandboxTokens(ctx context.Context, r *http.Request, rr *requests.Request, proof *user.User) (*user.User, *tokenrefresh.Result, error) {
	backend := p.getIdentityStoreByRealm(proof.Authenticator.Realm)
	if backend == nil {
		return nil, nil, fmt.Errorf("authentication realm not found")
	}
	if backend.GetName() != proof.Authenticator.Name || proof.LoginUsername == "" {
		return nil, nil, tokenrefresh.ErrDenied
	}
	if p.refreshRealm(proof.Authenticator.Realm) {
		if err := p.validateRefreshLogin(r, proof.RefreshTransport); err != nil {
			return nil, nil, err
		}
		principal := tokenrefresh.Principal{
			Backend: backend.GetName(), Realm: backend.GetRealm(), UserID: proof.LoginEvidence.UserID,
			Subject: proof.LoginUsername, CredentialVersion: proof.LoginEvidence.CredentialVersion,
			BackendVersion: proof.LoginEvidence.BackendVersion, AuthTime: proof.LoginEvidence.AuthenticatedAt,
			Methods: append([]string(nil), proof.LoginMethods...),
		}
		for _, c := range proof.Checkpoints {
			if !c.Passed {
				return nil, nil, tokenrefresh.ErrDenied
			}
			principal.Challenges = append(principal.Challenges, c.Type+":"+c.Parameters)
		}
		// Fresh browser login may replace a family even when admission is full.
		// Native credentials are independent of the browser's existing family.
		var previous []string
		if proof.RefreshTransport == tokenrefresh.CookieTransport {
			for _, c := range r.CookiesNamed(p.cookie.RefreshTokenCookieName) {
				previous = append(previous, c.Value)
			}
		}
		tokens, err := p.refresh.IssueReplacing(context.WithValue(ctx, refreshRequestContextKey{}, r), principal, proof.RefreshTransport, previous)
		if err != nil {
			return nil, nil, err
		}
		u, err := p.userFromRefresh(ctx, tokens)
		return u, tokens, err
	}
	// Local access-only issuance checks the same immutable account and security
	// version as renewable issuance, holding the identity transaction through
	// signing. Output claim transformations cannot change the account checked.
	if store, ok := backend.(refreshIdentityStore); ok {
		var u *user.User
		err := store.WithRefreshIdentity(ctx, proof.LoginEvidence, func(current identity.RefreshIdentity) error {
			var err error
			u, err = p.issueSandboxAccessToken(ctx, r, rr, proof, current)
			return err
		})
		if errors.Is(err, identity.ErrRefreshIdentityDenied) {
			err = tokenrefresh.ErrDenied
		}
		if err != nil {
			return nil, nil, err
		}
		return u, nil, nil
	}
	// Other stores retain their identification contract. Never use transformed
	// claims as lookup keys, including when a subject names an existing account.
	rr.User.Username, rr.User.Email = proof.LoginUsername, proof.LoginEmail
	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		return nil, nil, err
	}
	u, err := p.issueSandboxAccessToken(ctx, r, rr, proof, identity.RefreshIdentity{
		Username: rr.User.Username, Email: rr.User.Email, Name: rr.User.FullName,
		Roles: rr.User.Roles, Challenges: rr.User.Challenges, AuthMethods: rr.User.AuthMethods,
	})
	return u, nil, err
}

// issueSandboxAccessToken retains the configured access-only lifetime and
// reapplies transformations to current backend attributes, not sandbox claims.
func (p *Portal) issueSandboxAccessToken(ctx context.Context, r *http.Request, rr *requests.Request, proof *user.User, current identity.RefreshIdentity) (*user.User, error) {
	if current.Username != proof.LoginUsername || current.Email != proof.LoginEmail {
		return nil, tokenrefresh.ErrDenied
	}
	m := map[string]any{"sub": current.Username, "email": current.Email, "name": current.Name, "roles": current.Roles, "origin": proof.Authenticator.Realm, "realm": proof.Authenticator.Realm, "iss": util.GetIssuerURL(r), "addr": addrutil.GetSourceAddress(r)}
	now := time.Now().Unix()
	m["jti"], m["iat"], m["nbf"], m["exp"] = rr.Upstream.SessionID, now, now-60, now+int64(p.keystore.GetTokenLifetime(nil, nil))
	rr.User.Challenges = append([]string(nil), current.Challenges...)
	rr.User.AuthMethods = append([]string(nil), current.AuthMethods...)
	if err := p.transformUser(ctx, rr, m); err != nil {
		return nil, err
	}
	// Current policy may require additional factors since this sandbox began.
	candidate := &user.User{}
	if err := p.injectUserChallenges(candidate, m, rr.User.Challenges); err != nil {
		return nil, tokenrefresh.ErrDenied
	}
	completed := make([]string, 0, len(proof.Checkpoints))
	for _, checkpoint := range proof.Checkpoints {
		if checkpoint == nil || !checkpoint.Passed {
			return nil, tokenrefresh.ErrDenied
		}
		completed = append(completed, checkpoint.Type+":"+checkpoint.Parameters)
	}
	for _, required := range candidate.Checkpoints {
		if !satisfiedRefreshChallenge(required, completed) {
			return nil, tokenrefresh.ErrDenied
		}
	}
	delete(m, "amr")
	if len(proof.LoginMethods) > 0 {
		m["amr"] = append([]string(nil), proof.LoginMethods...)
	}
	injectPortalRoles(m, p.config)
	u, err := user.NewUser(m)
	if err != nil {
		return nil, err
	}
	u.Authenticator = user.Authenticator{Name: proof.Authenticator.Name, Realm: proof.Authenticator.Realm, Method: proof.Authenticator.Method}
	u.LoginEvidence = proof.LoginEvidence
	u.LoginUsername, u.LoginEmail = current.Username, current.Email
	u.LoginMethods = append([]string(nil), proof.LoginMethods...)
	if v, exists := m["frontend_links"]; exists {
		if err := u.AddFrontendLinks(v); err != nil {
			return nil, err
		}
	}
	if err := p.keystore.SignToken(nil, nil, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (p *Portal) userFromRefresh(ctx context.Context, tokens *tokenrefresh.Result) (*user.User, error) {
	if tokens == nil {
		return nil, tokenrefresh.ErrDenied
	}
	principal := tokens.Principal
	backend := p.getIdentityStoreByRealm(principal.Realm)
	store, ok := backend.(refreshIdentityStore)
	if !ok || backend.GetName() != principal.Backend || !p.refreshRealm(principal.Realm) {
		return nil, tokenrefresh.ErrDenied
	}
	evidence := requests.AuthenticationEvidence{
		UserID: principal.UserID, BackendVersion: principal.BackendVersion,
		CredentialVersion: principal.CredentialVersion, AuthenticatedAt: principal.AuthTime,
	}
	var current identity.RefreshIdentity
	err := store.WithRefreshIdentity(ctx, evidence, func(snapshot identity.RefreshIdentity) error {
		if snapshot.Username != principal.Subject {
			return tokenrefresh.ErrDenied
		}
		current = snapshot
		return nil
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		err = tokenrefresh.ErrDenied
	}
	if err != nil {
		return nil, err
	}
	u, err := user.NewUser(tokens.Claims)
	if err != nil {
		return nil, err
	}
	u.Token, u.TokenName = tokens.AccessToken, p.cookie.AccessTokenCookieName
	u.Authorized = true
	u.Authenticator = user.Authenticator{Name: backend.GetName(), Realm: backend.GetRealm(), Method: backend.GetKind()}
	u.LoginEvidence = evidence
	u.LoginUsername, u.LoginEmail = current.Username, current.Email
	u.LoginMethods = append([]string(nil), principal.Methods...)
	if v, ok := tokens.Claims["frontend_links"]; ok {
		if err := u.AddFrontendLinks(v); err != nil {
			return nil, err
		}
	}
	return u, nil
}
