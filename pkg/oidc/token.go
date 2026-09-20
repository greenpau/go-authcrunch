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
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

func (o *Provider) authenticateClient(r *http.Request, params url.Values) *ClientConfig {
	method, id, secret := "none", params.Get("client_id"), params.Get("client_secret")
	authorization := r.Header.Values("Authorization")
	if len(authorization) > 1 {
		return nil
	}
	if len(authorization) == 1 {
		// A body secret would introduce a second authentication mechanism.
		// An optional body identifier is permitted only when it matches Basic.
		if _, exists := params["client_secret"]; exists {
			return nil
		}
		basicID, basicSecret, ok := r.BasicAuth()
		if !ok {
			return nil
		}
		var err error
		id, err = url.QueryUnescape(basicID)
		if err != nil {
			return nil
		}
		if bodyID, exists := params["client_id"]; exists && (len(bodyID) != 1 || bodyID[0] != id) {
			return nil
		}
		secret, err = url.QueryUnescape(basicSecret)
		if err != nil {
			return nil
		}
		method = "client_secret_basic"
	} else if _, exists := params["client_secret"]; exists {
		method = "client_secret_post"
	}
	client := o.clients[id]
	// Hash comparisons keep secret length and unknown client lookups out of
	// the comparison timing. Secrets are high entropy registration values.
	expected := sha256.Sum256(nil)
	if client != nil {
		expected = sha256.Sum256([]byte(client.ClientSecret))
	}
	supplied := sha256.Sum256([]byte(secret))
	valid := subtle.ConstantTimeCompare(expected[:], supplied[:]) == 1
	if client == nil || !valid || client.TokenEndpointAuthMethod != method {
		return nil
	}
	return client
}

func (o *Provider) token(w http.ResponseWriter, r *http.Request) {
	if !oidcMethod(w, r, "POST") {
		return
	}
	params, err := oidcParameters(w, r, false)
	if err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client := o.authenticateClient(r, params)
	if client == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
		oidcError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if params.Get("grant_type") == "refresh_token" {
		o.refreshToken(w, r, params, client)
		return
	}
	if params.Get("grant_type") != "authorization_code" {
		oidcError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	if params.Get("code") == "" || params.Get("redirect_uri") == "" {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.persistResponse(w)
	o.sweep()
	grant := o.grants[sha256.Sum256([]byte(params.Get("code")))]
	if o.closed || grant == nil || grant.request.clientID != client.ClientID {
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// Retain spent-code tombstones until the resulting token expires. A
	// repeated redemption revokes that token, including concurrent replays.
	if grant.redeemed {
		o.revokeGrant(grant)
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !o.now().Before(grant.codeExpires) || grant.request.redirectURI != params.Get("redirect_uri") || !oidcVerifyPKCE(grant.request.challenge, params.Get("code_verifier")) {
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if grant.revoked || (slices.Contains(grant.request.scopes, "offline_access") && len(o.refresh) >= o.config.MaxRefreshTokens) {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	response, err := o.issueTokens(r, grant, client, false)

	if err != nil {
		if errors.Is(err, state.ErrCapacity) {
			oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		} else {
			oidcError(w, http.StatusBadRequest, "invalid_grant")
		}
		return
	}
	oidcJSON(w, r, response)
}

func oidcVerifyPKCE(challenge, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && !strings.ContainsRune("-._~", c) {
			return false
		}
	}
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(challenge)) == 1
}

func (o *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	if !oidcMethod(w, r, "GET", "POST") {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	credential := ""
	headers := r.Header.Values("Authorization")
	if len(headers) == 1 {
		scheme, value, ok := strings.Cut(headers[0], " ")
		if ok && strings.EqualFold(scheme, "Bearer") && !strings.ContainsAny(value, " \t\r\n") {
			credential = value
		}
	}
	if r.Method == http.MethodPost && (r.ContentLength != 0 || r.Header.Get("Content-Type") != "") {
		params, err := oidcParameters(w, r, false)
		if err != nil {
			oidcError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if _, exists := params["access_token"]; exists {
			if len(headers) != 0 {
				oidcError(w, http.StatusBadRequest, "invalid_request")
				return
			}
			credential = params.Get("access_token")
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.persistResponse(w)
	o.sweep()
	grant := o.access[sha256.Sum256([]byte(credential))]
	if o.closed || len(credential) != 43 || grant == nil || !o.now().Before(grant.accessExpires) || grant.revoked {
		oidcInvalidBearer(w)
		return
	}
	var result map[string]any
	err := o.withIdentity(r.Context(), o.sessions[grant.session], func(current map[string]any) error {
		result = map[string]any{"sub": current["sub"]}
		session := o.sessions[grant.session]
		current["auth_time"] = session.proof.AuthenticatedAt
		current["amr"] = slices.Clone(session.methods)
		if acr := o.authenticationContext(session, &grant.request); acr != "" {
			current["acr"] = acr
		}
		oidcDisclose(result, current, &grant.request, "userinfo")
		return nil
	})
	if err != nil {
		oidcInvalidBearer(w)
		return
	}
	oidcJSON(w, r, result)
}

func oidcInvalidBearer(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	oidcError(w, http.StatusUnauthorized, "invalid_token")
}

func (o *Provider) revoke(w http.ResponseWriter, r *http.Request) {
	if !oidcMethod(w, r, "POST") {
		return
	}
	params, err := oidcParameters(w, r, false)
	if err != nil || params.Get("token") == "" {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client := o.authenticateClient(r, params)
	if client == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
		oidcError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.persistResponse(w)
	hash := sha256.Sum256([]byte(params.Get("token")))
	if grant := o.access[hash]; grant != nil && grant.request.clientID == client.ClientID {
		o.revokeGrant(grant)
	}
	if grant := o.refresh[hash]; grant != nil && grant.request.clientID == client.ClientID {
		o.revokeGrant(grant)
	}
	w.WriteHeader(http.StatusOK)
}
