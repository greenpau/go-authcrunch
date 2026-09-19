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
	"slices"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// withDirectAuthenticationIdentity binds direct issuance to the verified local
// credential. Identification is not authentication, and must not replace this
// proof. Hold the identity transaction through policy evaluation and signing;
// callers must deliver tokens and modify sessions only after the callback ends.
func (p *Portal) withDirectAuthenticationIdentity(ctx context.Context, rr *requests.Request, apply func() error) error {
	backend := p.getIdentityStoreByRealm(rr.Upstream.Realm)
	store, ok := backend.(refreshIdentityStore)
	if !ok {
		// Other stores retain their existing authentication contract.
		return apply()
	}
	proof := rr.Authentication
	if proof.AuthenticatedAt == 0 || (proof.Method != "pwd" && proof.Method != "api_key") {
		rr.Response.Code = http.StatusUnauthorized
		return identity.ErrRefreshIdentityDenied
	}
	err := store.WithRefreshIdentity(ctx, proof, func(current identity.RefreshIdentity) error {
		if current.Username != rr.User.Username || current.Email != rr.User.Email {
			return identity.ErrRefreshIdentityDenied
		}
		rr.User.FullName = current.Name
		rr.User.Roles = append([]string(nil), current.Roles...)
		rr.User.Challenges = append([]string(nil), current.Challenges...)
		rr.User.AuthMethods = append([]string(nil), current.AuthMethods...)
		rr.User.AuthChallengePolicy = current.AuthChallengePolicy
		return apply()
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		rr.Response.Code = http.StatusUnauthorized
	} else if err != nil && rr.Response.Code < http.StatusBadRequest {
		rr.Response.Code = http.StatusInternalServerError
	}
	return err
}

// issueDirectAuthenticationToken is shared by the public Basic/API-key proxy
// entry points. Completed methods are supplied only after credential validation.
func (p *Portal) issueDirectAuthenticationToken(ctx context.Context, rr *requests.Request, issuer, address string, completed []string) (*user.User, error) {
	var usr *user.User
	err := p.withDirectAuthenticationIdentity(ctx, rr, func() error {
		now := time.Now().Unix()
		claims := map[string]any{
			"sub": rr.User.Username, "email": rr.User.Email, "origin": rr.Upstream.Realm,
			"iss": issuer, "addr": address, "iat": now, "nbf": now - 60,
			"exp": now + int64(p.keystore.GetTokenLifetime(nil, nil)),
		}
		if rr.User.FullName != "" {
			claims["name"] = rr.User.FullName
		}
		if len(rr.User.Roles) > 0 {
			claims["roles"] = rr.User.Roles
		}
		if err := p.transformUser(ctx, rr, claims); err != nil {
			return err
		}
		if err := p.checkDirectAuthenticationPolicy(rr, claims, completed); err != nil {
			return err
		}
		delete(claims, "amr")
		if slices.Contains(completed, "password") {
			claims["amr"] = []string{"pwd"}
		}
		injectPortalRoles(claims, p.config)
		var err error
		usr, err = user.NewUser(claims)
		if err != nil {
			return err
		}
		return p.keystore.SignToken(nil, nil, usr)
	})
	if err != nil {
		return nil, err
	}
	return usr, nil
}
