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
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (o *Provider) authorize(w http.ResponseWriter, r *http.Request) {
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
	// Never redirect until BOTH the client and exact registered URI are known.
	if !slices.Contains(client.RedirectURIs, params.Get("redirect_uri")) {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	request := &oidcAuthorization{clientID: client.ClientID, redirectURI: params.Get("redirect_uri"), state: params.Get("state"), nonce: params.Get("nonce"), responseMode: "query", created: o.now(), expires: o.now().Add(oidcRequestLifetime * time.Second)}
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
		o.issueCode(w, r, request)
		return
	}
	if authenticated && !fresh && o.hasConsent(s, request) && !request.promptConsent {
		o.issueCode(w, r, request)
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
	return ""
}

func (o *Provider) continueAuthorization(w http.ResponseWriter, r *http.Request) {
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
		for _, scope := range request.scopes {
			if !slices.Contains(s.consents[request.clientID], scope) {
				s.consents[request.clientID] = append(s.consents[request.clientID], scope)
			}
		}
		approved = true
	}
	if approved {
		delete(o.pending, hash)
		o.cookie(w, o.requestCookie, "", -1)
		o.issueCode(w, r, request)
		return
	}
	o.consentPage(w, r, request)
}

// issueCode is called under the provider lock. Commit occurs inside the local
// identity transaction so revocation cannot interleave with code issuance.
func (o *Provider) issueCode(w http.ResponseWriter, r *http.Request, request *oidcAuthorization) {
	if len(o.grants) >= o.config.MaxGrants {
		o.authorizationResponse(w, r, request, "", "temporarily_unavailable")
		return
	}
	code := oidcRandom()
	err := o.withIdentity(r.Context(), o.sessions[request.session], func(map[string]any) error {
		now := o.now()
		o.grants[sha256.Sum256([]byte(code))] = &oidcGrant{request: *request, session: request.session, codeExpires: now.Add(oidcCodeLifetime * time.Second), expires: now.Add(time.Duration(oidcCodeLifetime+o.config.TokenLifetimeSeconds) * time.Second)}
		return nil
	})
	if err != nil {
		o.authorizationResponse(w, r, request, "", "login_required")
		return
	}
	o.authorizationResponse(w, r, request, code, "")
}

func (o *Provider) authorizationResponse(w http.ResponseWriter, r *http.Request, request *oidcAuthorization, code, failure string) {
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
		nonce := oidcRandom()
		target, _ := url.Parse(request.redirectURI)
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; frame-ancestors 'none'; base-uri 'none'; form-action %s://%s", nonce, target.Scheme, target.Host))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = o.formPostTemplate.Execute(w, map[string]any{"RedirectURI": request.redirectURI, "Values": values, "Nonce": nonce})
		return
	}
	target, _ := url.Parse(request.redirectURI)
	query := target.Query()
	maps.Copy(query, values)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (o *Provider) consentPage(w http.ResponseWriter, _ *http.Request, request *oidcAuthorization) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = o.consentTemplate.Execute(w, map[string]any{"Client": o.clients[request.clientID].ClientName, "Subject": o.sessions[request.session].username, "Scopes": request.scopes, "CSRF": request.consent, "Action": o.config.Issuer + "/oidc/continue"})
}

const oidcConsentTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authorize application</title><main><h1>Authorize {{.Client}}</h1><p>Signed in as {{.Subject}}.</p><p>This application requests access to:</p><ul>{{range .Scopes}}<li>{{if eq . "openid"}}Your account identifier{{else if eq . "profile"}}Your name and username{{else if eq . "email"}}Your email address{{end}}</li>{{end}}</ul><form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="decision" value="allow">Allow</button> <button name="decision" value="deny">Deny</button></form></main></html>`
const oidcFormPostTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Continue to application</title><form id="response" method="post" action="{{.RedirectURI}}">{{range $key, $values := .Values}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}<button type="submit">Continue</button></form><script nonce="{{.Nonce}}">document.getElementById('response').submit();</script></html>`
