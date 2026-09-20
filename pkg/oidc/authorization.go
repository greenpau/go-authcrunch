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
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

func (o *Provider) authorize(w *oidcHTTPResponse, r *http.Request) {
	if !oidcMethod(w, r, "GET", "POST") {
		return
	}
	params, err := oidcParameters(w, r, true)
	if err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client := o.clients[params.Get("client_id")]
	if client == nil {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	assembled, objectError := o.requestObjectParameters(params)
	if objectError == "" {
		params = assembled
	}
	// Validate the effective redirect against this registration before any
	// redirect. Native loopback clients may vary only the callback port.
	redirectURI := params.Get("redirect_uri")
	if !client.isValidRedirectURI(redirectURI) {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	request := &oidcAuthorization{clientID: client.ClientID, redirectURI: redirectURI, state: params.Get("state"), nonce: params.Get("nonce"), responseMode: "query", created: o.now(), expires: o.now().Add(oidcRequestLifetime * time.Second)}
	if params.Get("response_mode") == "form_post" {
		request.responseMode = "form_post"
	}
	if objectError != "" {
		o.authorizationResponse(w, r, request, "", objectError)
		return
	}
	if code := o.validateAuthorization(request, client, params); code != "" {
		o.authorizationResponse(w, r, request, "", code)
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.persistResponse(w)
	o.sweep()
	if o.closed {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	request.session = oidcCookieHash(r, o.sessionCookie)
	s := o.sessions[request.session]
	authenticated := o.withIdentity(r.Context(), s, func(map[string]any) error { return nil }) == nil
	fresh := request.promptLogin || (request.maxAge != nil && (*request.maxAge == 0 || (s != nil && o.now().Unix()-s.proof.AuthenticatedAt > *request.maxAge)))
	if request.hintSubject != "" && s != nil && s.subject != request.hintSubject {
		authenticated = false
	}
	if request.promptNone {
		if !authenticated || fresh {
			o.authorizationResponse(w, r, request, "", "login_required")
			return
		}
		if !o.hasConsent(s, request) {
			o.authorizationResponse(w, r, request, "", "consent_required")
			return
		}
		_ = o.issueCode(w, r, request)
		return
	}
	if authenticated && !fresh && o.hasConsent(s, request) && !request.promptConsent {
		_ = o.issueCode(w, r, request)
		return
	}
	if len(o.pending) >= o.config.MaxPendingRequests {
		o.authorizationResponse(w, r, request, "", "temporarily_unavailable")
		return
	}
	credential := oidcRandom()
	request.consent = oidcRandom()
	request.fresh = !authenticated || fresh
	// One pending interactive authorization per browser. A replaced transaction
	// cannot be resumed, replayed, or approved by a stale consent page.
	delete(o.pending, oidcCookieHash(r, o.requestCookie))
	o.pending[sha256.Sum256([]byte(credential))] = request
	o.cookie(w, o.requestCookie, credential, oidcRequestLifetime)
	if request.fresh {
		http.Redirect(w, r, o.loginURL, http.StatusSeeOther)
		return
	}
	o.consentPage(w, r, request)
}

func (o *Provider) validateAuthorization(request *oidcAuthorization, client *ClientConfig, params url.Values) string {
	if params.Get("response_type") == "" {
		return "invalid_request"
	}
	if params.Get("response_type") != "code" {
		return "unsupported_response_type"
	}
	if mode := params.Get("response_mode"); mode != "" && mode != "query" && mode != "form_post" {
		return "invalid_request"
	}
	for _, param := range []struct{ name, code string }{{"request_uri", "request_uri_not_supported"}, {"registration", "registration_not_supported"}} {
		if params.Get(param.name) != "" {
			return param.code
		}
	}
	scopes := strings.Fields(params.Get("scope"))
	if !slices.Contains(scopes, "openid") {
		return "invalid_scope"
	}
	for _, scope := range scopes {
		if slices.Contains(client.Scopes, scope) && !slices.Contains(request.scopes, scope) {
			request.scopes = append(request.scopes, scope)
		}
	}
	prompts := strings.Fields(params.Get("prompt"))
	for _, prompt := range prompts {
		switch prompt {
		case "none":
			request.promptNone = true
		case "login", "select_account":
			request.promptLogin = true
		case "consent":
			request.promptConsent = true
		default:
			return "invalid_request"
		}
	}
	if request.promptNone && len(prompts) != 1 {
		return "invalid_request"
	}
	if raw := params.Get("max_age"); raw != "" {
		if strings.IndexFunc(raw, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			return "invalid_request"
		}
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "invalid_request"
		}
		request.maxAge = &value
	}
	challenge, method := params.Get("code_challenge"), params.Get("code_challenge_method")
	if challenge == "" {
		if client.RequirePKCE || method != "" {
			return "invalid_request"
		}
	} else {
		decoded, err := base64.RawURLEncoding.DecodeString(challenge)
		if method != "S256" || err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != challenge {
			return "invalid_request"
		}
		request.challenge = challenge
	}
	if raw := params.Get("id_token_hint"); raw != "" {
		subject, err := o.hintSubject(raw, client.ClientID)
		if err != nil {
			return "invalid_request"
		}
		request.hintSubject = subject
	}
	if !request.promptConsent {
		request.scopes = slices.DeleteFunc(request.scopes, func(scope string) bool { return scope == "offline_access" })
	}
	claims, err := parseOIDCClaims(params.Get("claims"), client)
	if err != nil {
		return "invalid_request"
	}
	request.claims = claims
	request.acrValues = strings.Fields(params.Get("acr_values"))
	return ""
}

func (o *Provider) continueAuthorization(w *oidcHTTPResponse, r *http.Request) {
	if !oidcMethod(w, r, "GET", "POST") {
		return
	}
	params, err := oidcParameters(w, r, false)
	if err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.persistResponse(w)
	o.sweep()
	hash := oidcCookieHash(r, o.requestCookie)
	request := o.pending[hash]
	if o.closed || request == nil || !o.now().Before(request.expires) {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	session := oidcCookieHash(r, o.sessionCookie)
	if request.fresh || request.session != session || o.sessions[session] == nil {
		o.authorizationResponse(w, r, request, "", "login_required")
		return
	}
	// Completing an older sandbox after this request is not fresh password
	// evidence. Preserve the original authentication time through redemption.
	authenticatedAt := o.sessions[session].proof.AuthenticatedAt
	if (request.promptLogin && authenticatedAt < request.created.Unix()) || (request.maxAge != nil && request.created.Unix()-authenticatedAt > *request.maxAge) {
		o.authorizationResponse(w, r, request, "", "login_required")
		return
	}
	if err := o.withIdentity(r.Context(), o.sessions[session], func(map[string]any) error { return nil }); err != nil {
		o.authorizationResponse(w, r, request, "", "login_required")
		return
	}
	if request.hintSubject != "" && o.sessions[session].subject != request.hintSubject {
		o.authorizationResponse(w, r, request, "", "login_required")
		return
	}
	approved := o.hasConsent(o.sessions[session], request) && !request.promptConsent
	var previousConsent []string
	previousConsentExists := false
	if r.Method == http.MethodPost {
		if !o.sameOrigin(r) || subtle.ConstantTimeCompare([]byte(params.Get("csrf")), []byte(request.consent)) != 1 {
			oidcError(w, http.StatusForbidden, "invalid_request")
			return
		}
		if params.Get("decision") != "allow" && params.Get("decision") != "deny" {
			oidcError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		delete(o.pending, hash)
		o.cookie(w, o.requestCookie, "", -1)
		if params.Get("decision") == "deny" {
			o.authorizationResponse(w, r, request, "", "access_denied")
			return
		}
		s := o.sessions[session]
		if s.consents == nil {
			s.consents = make(map[string][]string)
		}
		previousConsent, previousConsentExists = s.consents[request.clientID]
		previousConsent = slices.Clone(previousConsent)
		for _, scope := range request.consentItems() {
			if !slices.Contains(s.consents[request.clientID], scope) {
				s.consents[request.clientID] = append(s.consents[request.clientID], scope)
			}
		}
		approved = true
	}
	if approved {
		delete(o.pending, hash)
		o.cookie(w, o.requestCookie, "", -1)
		if err := o.issueCode(w, r, request); err != nil && r.Method == http.MethodPost {
			if previousConsentExists {
				o.sessions[session].consents[request.clientID] = previousConsent
			} else {
				delete(o.sessions[session].consents, request.clientID)
			}
		}
		return
	}
	o.consentPage(w, r, request)
}

// issueCode is called under the provider lock. Commit occurs inside the local
// identity transaction so revocation cannot interleave with code issuance.
func (o *Provider) issueCode(w *oidcHTTPResponse, r *http.Request, request *oidcAuthorization) error {
	if len(o.grants) >= o.config.MaxGrants {
		o.authorizationResponse(w, r, request, "", "temporarily_unavailable")
		return errOIDCAdmission
	}
	if s := o.sessions[request.session]; s == nil || !o.satisfiesClaims(s, request) {
		o.authorizationResponse(w, r, request, "", "access_denied")
		return ErrIdentityDenied
	}
	code := oidcRandom()
	hash := sha256.Sum256([]byte(code))
	err := o.withIdentity(r.Context(), o.sessions[request.session], func(map[string]any) error {
		now := o.now()
		o.grants[hash] = &oidcGrant{request: *request, session: request.session, codeExpires: now.Add(oidcCodeLifetime * time.Second), expires: now.Add(time.Duration(oidcCodeLifetime+o.config.TokenLifetimeSeconds) * time.Second)}
		return o.persistState()
	})
	if err != nil {
		delete(o.grants, hash)
		if errors.Is(err, state.ErrCapacity) {
			o.authorizationResponse(w, r, request, "", "temporarily_unavailable")
		} else {
			o.authorizationResponse(w, r, request, "", "login_required")
		}
		return err
	}
	o.authorizationResponse(w, r, request, code, "")
	return nil
}

func (o *Provider) authorizationResponse(w *oidcHTTPResponse, r *http.Request, request *oidcAuthorization, code, failure string) {
	client := o.clients[request.clientID]
	redirectURI := request.redirectURI
	if client == nil || !client.isValidRedirectURI(redirectURI) {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	target, err := parseOIDCRedirectURI(redirectURI)
	if err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	values := url.Values{"iss": {o.config.Issuer}}
	if request.state != "" {
		values.Set("state", request.state)
	}
	if failure != "" {
		values.Set("error", failure)
	} else {
		values.Set("code", code)
	}
	if request.responseMode == "form_post" {
		w.page = &Page{Kind: "form_post", Title: "Continue to application",
			ClientName: client.ClientName, Action: redirectURI, Values: values}
		return
	}
	query := target.Query()
	maps.Copy(query, values)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}
