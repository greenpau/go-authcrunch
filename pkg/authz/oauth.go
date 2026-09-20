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

package authz

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authz/internal/uri"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// The provider owns protocol state. The gatekeeper separately binds the return
// URI and verified identity to an unguessable browser cookie and request origin.
// No upstream credential is retained in these stores or sent to the application.
type oauthLogin struct {
	claimed                          bool
	state, origin, returnURI, method string
	expires                          time.Time
}

type oauthSession struct {
	origin  string
	user    *user.User
	expires time.Time
}

type oauthLoginCanceler interface {
	CancelLogin(string, [32]byte, string) bool
}

type oauthAuthorization struct {
	config   OAuthAuthorizationConfig
	provider idp.IdentityProvider
	canceler oauthLoginCanceler
	mu       sync.Mutex
	closed   bool
	logins   map[[32]byte]oauthLogin
	sessions map[[32]byte]oauthSession
}

func newOAuthAuthorization(cfg *OAuthAuthorizationConfig, providers []idp.IdentityProvider) (*oauthAuthorization, error) {
	var selected idp.IdentityProvider
	for _, provider := range providers {
		if provider != nil && provider.GetName() == cfg.IdentityProvider {
			if selected != nil {
				return nil, fmt.Errorf("duplicate OAuth identity provider")
			}
			selected = provider
		}
	}
	if selected == nil || selected.GetKind() != "oauth" || !selected.Configured() {
		return nil, fmt.Errorf("authorization policy OAuth identity provider not found, not configured or not OAuth")
	}
	canceler, ok := selected.(oauthLoginCanceler)
	if !ok {
		return nil, fmt.Errorf("authorization policy OAuth identity provider does not support login cancellation")
	}
	// This adapter implements the authorization-code query callback, not the
	// portal's JavaScript or implicit-token handlers.
	pc := selected.GetConfig()
	if enabled, _ := pc["js_callback_enabled"].(bool); enabled {
		return nil, fmt.Errorf("direct OAuth does not support JavaScript callbacks")
	}
	if rt, exists := pc["response_type"]; exists {
		switch values := rt.(type) {
		case []string:
			if len(values) != 1 || values[0] != "code" {
				return nil, fmt.Errorf("direct OAuth requires code response type")
			}
		case []any:
			if len(values) != 1 || values[0] != "code" {
				return nil, fmt.Errorf("direct OAuth requires code response type")
			}
		default:
			return nil, fmt.Errorf("direct OAuth requires code response type")
		}
	}
	return &oauthAuthorization{config: *cfg, provider: selected, canceler: canceler, logins: make(map[[32]byte]oauthLogin), sessions: make(map[[32]byte]oauthSession)}, nil
}

func (o *oauthAuthorization) close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.closed = true
	logins := maps.Clone(o.logins)
	clear(o.logins)
	clear(o.sessions)
	o.mu.Unlock()
	o.cancelLogins(logins)
}

func (o *oauthAuthorization) cancelLogin(key [32]byte, login oauthLogin) bool {
	if o.canceler == nil || login.state == "" || login.origin == "" {
		return false
	}
	return o.canceler.CancelLogin(login.state, key, login.origin+o.config.CallbackPath())
}

func (o *oauthAuthorization) cancelLogins(logins map[[32]byte]oauthLogin) {
	for key, login := range logins {
		o.cancelLogin(key, login)
	}
}

// Expiry is checked on reads and reclaimed on admissions. The fixed capacity
// bounds both memory and cleanup work without adding a lifecycle worker.
func (o *oauthAuthorization) prune(now time.Time) map[[32]byte]oauthLogin {
	var expiredLogins map[[32]byte]oauthLogin
	for key, login := range o.logins {
		if !now.Before(login.expires) {
			if expiredLogins == nil {
				expiredLogins = make(map[[32]byte]oauthLogin)
			}
			expiredLogins[key] = login
			delete(o.logins, key)
		}
	}
	for key, session := range o.sessions {
		if !now.Before(session.expires) {
			delete(o.sessions, key)
		}
	}
	return expiredLogins
}

func (o *oauthAuthorization) ownsEndpoint(r *http.Request) bool {
	paths, _ := uri.RequestPaths(r)
	paths = append(paths, r.URL.Path)
	for _, p := range paths {
		if p == o.config.BasePath || strings.HasPrefix(p, o.config.BasePath+"/") {
			return true
		}
	}
	return false
}

func (o *oauthAuthorization) origin(r *http.Request) (string, bool) {
	// Never use X-Forwarded-Host/Proto or an absolute-form request target.
	origin := "https://" + r.Host
	u, err := url.Parse(origin)
	if err != nil || u.Host != r.Host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(r.Host, "\\\r\n\t /?#") {
		return "", false
	}
	if o.config.PublicOrigin != "" {
		return o.config.PublicOrigin, origin == o.config.PublicOrigin
	}
	return origin, r.TLS != nil
}

func oauthCredential() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func oauthCookie(r *http.Request, name string) (string, bool) {
	cookies := r.CookiesNamed(name)
	if len(cookies) == 0 {
		return "", true
	}
	if len(cookies) != 1 {
		return "", false
	}
	value := cookies[0].Value
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return value, err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func setOAuthCookie(w http.ResponseWriter, name, value string, lifetime int) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: lifetime}
	if lifetime < 0 {
		c.Expires = time.Unix(1, 0)
	} else {
		c.Expires = time.Now().Add(time.Duration(lifetime) * time.Second)
	}
	http.SetCookie(w, c)
}

func oauthResponse(w http.ResponseWriter, status int) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Error(w, http.StatusText(status), status)
	return nil
}

func (g *Gatekeeper) authenticateOAuth(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	o := g.oauth
	origin, valid := o.origin(r)
	if !valid {
		return oauthResponse(w, http.StatusBadRequest)
	}
	if o.ownsEndpoint(r) {
		// Endpoints are reserved before bypass/credential checks; alternate encoded
		// or cleaned interpretations must never become callback aliases.
		if r.URL.IsAbs() || r.URL.Host != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
			return oauthResponse(w, http.StatusBadRequest)
		}
		switch r.URL.Path {
		case o.config.CallbackPath():
			return g.completeOAuth(w, r, origin)
		case o.config.LogoutPath():
			return g.logoutOAuth(w, r, origin)
		default:
			return oauthResponse(w, http.StatusNotFound)
		}
	}
	credential, valid := oauthCookie(r, o.config.SessionCookieName)
	if !valid {
		return oauthResponse(w, http.StatusBadRequest)
	}
	if credential != "" {
		key := sha256.Sum256([]byte(credential))
		o.mu.Lock()
		session, exists := o.sessions[key]
		if exists && !time.Now().Before(session.expires) {
			delete(o.sessions, key)
			exists = false
		}
		if exists && session.origin == origin && !o.closed {
			usr := session.user.Clone()
			o.mu.Unlock()
			if err := g.tokenValidator.AuthorizeUser(r.Context(), r, usr); err != nil {
				ar.Response.Error = err
				return g.handleAuthorizeWithForbidden(w, r, ar)
			}
			usr.Token, usr.TokenName, usr.TokenSource = credential, o.config.SessionCookieName, "cookie"
			g.injectHeaders(r, usr)
			g.stripAuthToken(r, usr)
			ar.Response.User = usr.BuildRequestIdentity(g.config.UserIdentityField)
			ar.Response.Authorized = true
			return nil
		}
		o.mu.Unlock()
		setOAuthCookie(w, o.config.SessionCookieName, "", -1)
	}
	if g.config.AuthRedirectDisabled || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return oauthResponse(w, http.StatusUnauthorized)
	}
	return g.beginOAuth(w, r, origin, ar)
}

func oauthReturnURI(r *http.Request) (string, bool) {
	paths, valid := uri.RequestPaths(r)
	if !valid || r.URL.IsAbs() || r.URL.Opaque != "" || r.URL.Host != "" {
		return "", false
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
			return "", false
		}
	}
	target := r.URL.RequestURI()
	if len(target) > 8192 || strings.ContainsAny(target, "\r\n") {
		return "", false
	}
	return target, true
}

func (o *oauthAuthorization) request(r *http.Request, origin, browser string) *requests.Request {
	return &requests.Request{Upstream: requests.Upstream{Request: r, BaseURL: origin, BasePath: o.config.BasePath, SessionID: browser}}
}

func (g *Gatekeeper) beginOAuth(w http.ResponseWriter, r *http.Request, origin string, ar *requests.AuthorizationRequest) error {
	o := g.oauth
	target, valid := oauthReturnURI(r)
	if !valid {
		return oauthResponse(w, http.StatusBadRequest)
	}
	previous, valid := oauthCookie(r, o.config.LoginCookieName)
	if !valid {
		return oauthResponse(w, http.StatusBadRequest)
	}
	browser := oauthCredential()
	key := sha256.Sum256([]byte(browser))
	o.mu.Lock()
	expiredLogins := o.prune(time.Now())
	previousKey := sha256.Sum256([]byte(previous))
	var replaced oauthLogin
	var replacedLogin bool
	if p, exists := o.logins[previousKey]; exists && p.origin == origin {
		replaced = p
		replacedLogin = true
		delete(o.logins, previousKey)
	}
	admissionRejected := o.closed || len(o.logins) >= o.config.MaxPendingLogins
	if admissionRejected {
		o.mu.Unlock()
		o.cancelLogins(expiredLogins)
		if replacedLogin {
			o.cancelLogin(previousKey, replaced)
		}
		return oauthResponse(w, http.StatusServiceUnavailable)
	}
	o.logins[key] = oauthLogin{origin: origin, returnURI: target, method: r.Method, expires: time.Now().Add(oauthLoginLifetime * time.Second)}
	o.mu.Unlock()
	o.cancelLogins(expiredLogins)
	if replacedLogin {
		o.cancelLogin(previousKey, replaced)
	}
	// Application query parameters must not be interpreted as OAuth responses or
	// override state, callback, scope, or nonce. Only validated opt-in hints pass.
	request := r.Clone(r.Context())
	request.URL.RawQuery = ""
	request.URL.ForceQuery = false
	hints := url.Values{}
	if len(g.config.LoginHintValidators) != 0 {
		g.handleLoginHint(r, ar)
		if ar.Redirect.LoginHint != "" {
			hints.Set("login_hint", ar.Redirect.LoginHint)
		}
	}
	if g.config.AdditionalScopes {
		g.handleAdditionalScopes(r, ar)
		if ar.Redirect.AdditionalScopes != "" {
			hints.Set("additional_scopes", ar.Redirect.AdditionalScopes)
		}
	}
	request.URL.RawQuery = hints.Encode()
	rr := o.request(request, origin, browser)
	err := o.provider.Request(operator.Authenticate, rr)
	redirect, parseErr := url.Parse(rr.Response.RedirectURL)
	o.mu.Lock()
	login, exists := o.logins[key]
	state := ""
	if redirect != nil {
		state = redirect.Query().Get("state")
	}
	if !exists || err != nil || parseErr != nil || redirect == nil || redirect.Scheme != "https" || redirect.Host == "" || state == "" || rr.Response.Code != http.StatusFound || o.closed {
		delete(o.logins, key)
		o.mu.Unlock()
		o.cancelLogin(key, oauthLogin{state: state, origin: origin})
		return oauthResponse(w, http.StatusBadGateway)
	}
	login.state = state
	o.logins[key] = login
	o.mu.Unlock()
	setOAuthCookie(w, o.config.LoginCookieName, browser, oauthLoginLifetime)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, redirect.String(), http.StatusFound)
	return nil
}

func (g *Gatekeeper) completeOAuth(w http.ResponseWriter, r *http.Request, origin string) error {
	o := g.oauth
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		return oauthResponse(w, http.StatusMethodNotAllowed)
	}
	if len(r.URL.RawQuery) > 16384 {
		return oauthResponse(w, http.StatusBadRequest)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return oauthResponse(w, http.StatusBadRequest)
	}
	for _, name := range []string{"state", "code", "error", "error_description", "iss"} {
		if entries, exists := values[name]; exists && (len(entries) != 1 || entries[0] == "") {
			return oauthResponse(w, http.StatusBadRequest)
		}
	}
	if values.Get("state") == "" || (values.Get("code") == "") == (values.Get("error") == "") || values.Has("id_token") || values.Has("access_token") {
		return oauthResponse(w, http.StatusBadRequest)
	}
	browser, valid := oauthCookie(r, o.config.LoginCookieName)
	if !valid || browser == "" {
		return oauthResponse(w, http.StatusBadRequest)
	}
	key := sha256.Sum256([]byte(browser))
	o.mu.Lock()
	login, exists := o.logins[key]
	if !exists || login.claimed || o.closed || login.origin != origin || login.state != values.Get("state") || !time.Now().Before(login.expires) {
		o.mu.Unlock()
		return oauthResponse(w, http.StatusBadRequest)
	}
	// Keep a claimed record until completion: it bounds concurrent exchanges
	// and lets logout, a replacement login, or Close cancel in-flight issuance.
	login.claimed = true
	o.logins[key] = login
	o.mu.Unlock()
	defer func() { o.mu.Lock(); delete(o.logins, key); o.mu.Unlock() }()
	setOAuthCookie(w, o.config.LoginCookieName, "", -1)
	rr := o.request(r, origin, browser)
	if err := o.provider.Request(operator.Authenticate, rr); err != nil || rr.Response.Code != http.StatusOK {
		return oauthResponse(w, http.StatusUnauthorized)
	}
	usr, err := o.identity(rr.Response.Payload, r, origin)
	if err != nil {
		return oauthResponse(w, http.StatusUnauthorized)
	}
	// Authorize the resource that initiated login, not the public callback path.
	target := r.Clone(r.Context())
	target.URL, err = url.ParseRequestURI(login.returnURI)
	if err != nil {
		return oauthResponse(w, http.StatusBadRequest)
	}
	target.RequestURI = login.returnURI
	target.Method = login.method
	if err := g.tokenValidator.AuthorizeUser(r.Context(), target, usr); err != nil {
		return oauthResponse(w, http.StatusForbidden)
	}
	credential := oauthCredential()
	sessionKey := sha256.Sum256([]byte(credential))
	o.mu.Lock()
	current, active := o.logins[key]
	if o.closed || !active || !current.claimed || !time.Now().Before(current.expires) {
		o.mu.Unlock()
		return oauthResponse(w, http.StatusUnauthorized)
	}
	expiredLogins := o.prune(time.Now())
	previous, valid := oauthCookie(r, o.config.SessionCookieName)
	if !valid {
		o.mu.Unlock()
		o.cancelLogins(expiredLogins)
		return oauthResponse(w, http.StatusBadRequest)
	}
	previousKey := sha256.Sum256([]byte(previous))
	if s, ok := o.sessions[previousKey]; ok && s.origin == origin {
		delete(o.sessions, previousKey)
	}
	if o.closed || len(o.sessions) >= o.config.MaxSessions {
		o.mu.Unlock()
		o.cancelLogins(expiredLogins)
		return oauthResponse(w, http.StatusServiceUnavailable)
	}
	expires := time.Now().Add(time.Duration(o.config.SessionLifetime) * time.Second)
	o.sessions[sessionKey] = oauthSession{origin: origin, user: usr, expires: expires}
	o.mu.Unlock()
	o.cancelLogins(expiredLogins)
	setOAuthCookie(w, o.config.SessionCookieName, credential, o.config.SessionLifetime)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, login.returnURI, http.StatusSeeOther)
	return nil
}

func (o *oauthAuthorization) identity(payload any, r *http.Request, origin string) (*user.User, error) {
	claims, ok := payload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid OAuth identity")
	}
	// Set the baseline role before user normalization, so a verified identity
	// without provider roles does not acquire the generic anonymous/guest fallback.
	data := maps.Clone(claims)
	switch roles := data["roles"].(type) {
	case nil:
		data["roles"] = []string{"authp/user"}
	case string:
		data["roles"] = roles + " authp/user"
	case []string:
		data["roles"] = append(slices.Clone(roles), "authp/user")
	case []any:
		data["roles"] = append(slices.Clone(roles), "authp/user")
	default:
		return nil, fmt.Errorf("invalid OAuth identity")
	}
	data["origin"] = o.provider.GetRealm()
	data["realm"] = o.provider.GetRealm()
	data["iss"] = origin
	data["addr"] = addrutil.GetSourceAddress(r)
	data["iat"] = time.Now().Unix()
	data["nbf"] = time.Now().Unix()
	data["exp"] = time.Now().Add(time.Duration(o.config.SessionLifetime) * time.Second).Unix()
	data["jti"] = oauthCredential()
	usr, err := user.NewUser(data)
	if err != nil || strings.TrimSpace(usr.Claims.Subject) == "" {
		return nil, fmt.Errorf("invalid OAuth identity")
	}

	usr.Authenticator.Name = o.provider.GetName()
	usr.Authenticator.Realm = o.provider.GetRealm()
	usr.Authenticator.Method = "oauth2"
	return usr, nil
}

func (g *Gatekeeper) logoutOAuth(w http.ResponseWriter, r *http.Request, origin string) error {
	o := g.oauth
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return oauthResponse(w, http.StatusMethodNotAllowed)
	}
	if r.Header.Get("Origin") != origin || len(r.Header.Values("Origin")) != 1 {
		return oauthResponse(w, http.StatusForbidden)
	}
	session, sessionOK := oauthCookie(r, o.config.SessionCookieName)
	login, loginOK := oauthCookie(r, o.config.LoginCookieName)
	if !sessionOK || !loginOK {
		return oauthResponse(w, http.StatusBadRequest)
	}
	o.mu.Lock()
	sessionKey, loginKey := sha256.Sum256([]byte(session)), sha256.Sum256([]byte(login))
	if s, exists := o.sessions[sessionKey]; exists && s.origin == origin {
		delete(o.sessions, sessionKey)
	}
	removedLogin, removed := o.logins[loginKey]
	if removed && removedLogin.origin == origin {
		delete(o.logins, loginKey)
	} else {
		removed = false
	}
	o.mu.Unlock()
	if removed {
		o.cancelLogin(loginKey, removedLogin)
	}
	setOAuthCookie(w, o.config.SessionCookieName, "", -1)
	setOAuthCookie(w, o.config.LoginCookieName, "", -1)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return nil
}
