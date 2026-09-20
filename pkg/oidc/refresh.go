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

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

// Each code owns one family. Spent refresh hashes remain until the absolute
// family expiry for replay detection. MaxRefreshTokens bounds active plus spent
// credentials globally; reaching it cannot evict evidence or extend a family.
func (o *Provider) revokeGrant(grant *oidcGrant) {
	grant.revoked = true
	delete(o.access, grant.accessHash)
}
func (o *Provider) refreshToken(w http.ResponseWriter, r *http.Request, params url.Values, client *ClientConfig) {
	credential := params.Get("refresh_token")
	if credential == "" {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.persistResponse(w)
	o.sweep()
	hash := sha256.Sum256([]byte(credential))
	grant := o.refresh[hash]
	if o.closed || len(credential) != 43 || grant == nil || grant.request.clientID != client.ClientID || grant.revoked || !o.now().Before(grant.expires) {
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if hash != grant.refreshCurrent {
		o.revokeGrant(grant)
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	scopes := grant.request.scopes
	if raw, ok := params["scope"]; ok {
		scopes = strings.Fields(raw[0])
		if len(scopes) == 0 || !oidcUniqueStrings(scopes) || slices.ContainsFunc(scopes, func(s string) bool { return !slices.Contains(grant.request.scopes, s) }) {
			oidcError(w, http.StatusBadRequest, "invalid_scope")
			return
		}
	}
	if len(o.refresh) >= o.config.MaxRefreshTokens {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	// Narrowing is permanent for this family and commits only with issuance.
	original := grant.request.scopes
	grant.request.scopes = slices.Clone(scopes)
	response, err := o.issueTokens(r, grant, client, true)
	if err != nil {
		if errors.Is(err, state.ErrCapacity) {
			grant.request.scopes = original
			oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		} else {
			grant.request.scopes = original
			o.revokeGrant(grant)
			oidcError(w, http.StatusBadRequest, "invalid_grant")
		}
		return
	}
	oidcJSON(w, r, response)
}
func (o *Provider) issueTokens(r *http.Request, grant *oidcGrant, client *ClientConfig, refresh bool) (map[string]any, error) {
	session := o.sessions[grant.session]
	previous := *grant
	previous.request.scopes = slices.Clone(grant.request.scopes)
	previous.refreshHashes = slices.Clone(grant.refreshHashes)
	previousAccess := o.access[grant.accessHash]
	var response map[string]any
	err := o.withIdentity(r.Context(), session, func(current map[string]any) error {
		now := o.now()
		expires := now.Add(time.Duration(o.config.TokenLifetimeSeconds) * time.Second)
		if session.expires.Before(expires) {
			expires = session.expires
		}
		familyExpires := grant.expires
		if !refresh && slices.Contains(grant.request.scopes, "offline_access") {
			familyExpires = now.Add(time.Duration(o.config.RefreshLifetimeSeconds) * time.Second)
			if session.expires.Before(familyExpires) {
				familyExpires = session.expires
			}
		}
		if (refresh || slices.Contains(grant.request.scopes, "offline_access")) && familyExpires.Before(expires) {
			expires = familyExpires
		}
		if expires.Unix() <= now.Unix() || !o.satisfiesClaims(session, &grant.request) {
			return ErrIdentityDenied
		}
		access := oidcRandom()
		digest := sha256.Sum256([]byte(access))
		claims := map[string]any{"iss": o.config.Issuer, "sub": session.subject, "aud": client.ClientID, "iat": now.Unix(), "exp": expires.Unix(), "auth_time": session.proof.AuthenticatedAt, "amr": slices.Clone(session.methods), "at_hash": base64.RawURLEncoding.EncodeToString(digest[:16])}
		if grant.request.nonce != "" {
			claims["nonce"] = grant.request.nonce
		}
		if acr := o.authenticationContext(session, &grant.request); acr != "" {
			claims["acr"] = acr
		}
		oidcDisclose(claims, current, &grant.request, "id_token")
		idToken, err := o.sign(claims)
		if err != nil {
			return err
		}
		response = map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": expires.Unix() - now.Unix(), "id_token": idToken, "scope": strings.Join(grant.request.scopes, " ")}
		if !slices.Contains(grant.request.scopes, "openid") {
			delete(response, "id_token")
		}
		// Every fallible operation precedes the serialized state commit.
		if !refresh {
			grant.expires = expires
		}
		if refresh || slices.Contains(grant.request.scopes, "offline_access") {
			if !refresh {
				grant.expires = familyExpires
			}
			token := oidcRandom()
			hash := sha256.Sum256([]byte(token))
			grant.refreshCurrent = hash
			grant.refreshHashes = append(grant.refreshHashes, hash)
			o.refresh[hash] = grant
			response["refresh_token"] = token
		}
		delete(o.access, grant.accessHash)
		grant.redeemed, grant.accessHash, grant.accessExpires = true, digest, expires
		o.access[digest] = grant
		return o.persistState()
	})
	if errors.Is(err, state.ErrCapacity) {
		delete(o.access, grant.accessHash)
		for _, hash := range grant.refreshHashes[len(previous.refreshHashes):] {
			delete(o.refresh, hash)
		}
		*grant = previous
		if previousAccess != nil {
			o.access[previous.accessHash] = previousAccess
		}
	}
	return response, err
}
