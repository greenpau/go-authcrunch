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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// issueSandboxTokens is shared by browser and JSON login after atomic redemption.
func (p *Portal) issueSandboxTokens(ctx context.Context, r *http.Request, rr *requests.Request, proof *user.User) (*user.User, *refresh.Result, error) {
	backend := p.getIdentityStoreByRealm(proof.Authenticator.Realm)
	if backend == nil {
		return nil, nil, fmt.Errorf("authentication realm not found")
	}
	if p.refreshRealm(proof.Authenticator.Realm) {
		if err := p.validateRefreshLogin(r, proof.RefreshTransport); err != nil {
			return nil, nil, err
		}
		principal := refresh.Principal{
			Backend: backend.GetName(), Realm: backend.GetRealm(), UserID: proof.LoginEvidence.UserID,
			Subject: proof.Claims.Subject, CredentialVersion: proof.LoginEvidence.CredentialVersion,
			BackendVersion: proof.LoginEvidence.BackendVersion, AuthTime: proof.LoginEvidence.AuthenticatedAt,
			Methods: append([]string(nil), proof.LoginMethods...),
		}
		for _, c := range proof.Checkpoints {
			if !c.Passed {
				return nil, nil, refresh.ErrDenied
			}
			principal.Challenges = append(principal.Challenges, c.Type+":"+c.Parameters)
		}
		tokens, err := p.refresh.Issue(context.WithValue(ctx, refreshRequestContextKey{}, r), principal, proof.RefreshTransport)
		if err != nil {
			return nil, nil, err
		}
		u, err := p.userFromRefresh(tokens)
		return u, tokens, err
	}
	// Access-only realms retain their configured access-token lifetime.
	rr.User.Username = proof.Claims.Subject
	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		return nil, nil, err
	}
	if rr.User.Username != proof.Claims.Subject || rr.User.Email != proof.Claims.Email {
		return nil, nil, refresh.ErrDenied
	}
	m := map[string]any{"sub": rr.User.Username, "email": rr.User.Email, "name": rr.User.FullName, "roles": rr.User.Roles, "origin": backend.GetRealm(), "realm": backend.GetRealm(), "iss": util.GetIssuerURL(r), "addr": addrutil.GetSourceAddress(r)}
	now := time.Now().Unix()
	m["jti"], m["iat"], m["nbf"], m["exp"] = rr.Upstream.SessionID, now, now-60, now+int64(p.keystore.GetTokenLifetime(nil, nil))
	if err := p.transformUser(ctx, rr, m); err != nil {
		return nil, nil, err
	}
	injectPortalRoles(m, p.config)
	u, err := user.NewUser(m)
	if err != nil {
		return nil, nil, err
	}
	u.Authenticator = user.Authenticator{Name: backend.GetName(), Realm: backend.GetRealm(), Method: backend.GetKind()}
	if v, exists := m["frontend_links"]; exists {
		if err := u.AddFrontendLinks(v); err != nil {
			return nil, nil, err
		}
	}
	if err := p.keystore.SignToken(nil, nil, u); err != nil {
		return nil, nil, err
	}
	return u, nil, nil
}

func (p *Portal) userFromRefresh(tokens *refresh.Result) (*user.User, error) {
	u, err := user.NewUser(tokens.Claims)
	if err != nil {
		return nil, err
	}
	u.Token, u.TokenName = tokens.AccessToken, p.cookie.AccessTokenCookieName
	u.Authorized = true
	backend := p.getIdentityStoreByRealm(u.Claims.Origin)
	if backend == nil {
		return nil, refresh.ErrDenied
	}
	u.Authenticator = user.Authenticator{Name: backend.GetName(), Realm: backend.GetRealm(), Method: backend.GetKind()}
	if v, ok := tokens.Claims["frontend_links"]; ok {
		if err := u.AddFrontendLinks(v); err != nil {
			return nil, err
		}
	}
	return u, nil
}
