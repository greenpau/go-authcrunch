// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/handlers"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"github.com/greenpau/go-authcrunch/pkg/util/validate"
	"go.uber.org/zap"
)

const (
	claimHeaderUserName  = "X-Token-User-Name"
	claimHeaderUserEmail = "X-Token-User-Email"
	claimHeaderUserRoles = "X-Token-User-Roles"
	claimHeaderSubject   = "X-Token-Subject"
)

// Authenticate authorizes HTTP requests.
func (g *Gatekeeper) Authenticate(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	// The gatekeeper owns configured identity headers on every request. Clear
	// client values before any branch can return or reach downstream code.
	g.stripInjectedHeaders(r)
	if g.closed.Load() {
		ar.Response.Authorized = false
		ar.Response.Bypassed = false
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return nil
	}
	ar.Response.Authorized = false
	ar.Response.Bypassed = false
	if g.oauth != nil && g.oauth.ownsEndpoint(r) {
		return g.authenticateOAuth(w, r, ar)
	}
	// Perform authorization bypass checks
	if g.bypassEnabled && bypass.Match(r, g.config.BypassConfigs) {
		ar.Response.Authorized = false
		ar.Response.Bypassed = true
		g.logger.Info(
			"authorization bypassed",
			zap.String("session_id", ar.SessionID),
			zap.String("request_id", ar.ID),
			zap.String("src_ip", addrutil.GetSourceAddress(r)),
			zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
			zap.String("url", addrutil.GetTargetURL(r)),
		)
		return nil
	}

	if g.oauth != nil {
		return g.authenticateOAuth(w, r, ar)
	}
	g.parseSessionID(r, ar)

	usr, err := g.tokenValidator.Authorize(context.Background(), r, ar)
	if err != nil {
		ar.Response.Error = err
		return g.handleUnauthorizedUser(w, r, ar)
	}
	return g.handleAuthorizedUser(w, r, ar, usr)
}

// handleAuthorizedUser handles authorized requests.
func (g *Gatekeeper) handleAuthorizedUser(_ http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest, usr *user.User) error {
	g.injectHeaders(r, usr)
	g.stripAuthToken(r, usr)

	ar.Response.Authorized = true

	if usr.Cached {
		ar.Response.User = usr.GetRequestIdentity()
		return nil
	}

	ar.Response.User = usr.BuildRequestIdentity(g.config.UserIdentityField)

	if err := g.tokenValidator.CacheUser(usr); err != nil {
		g.logger.Error(
			"token caching error",
			zap.String("session_id", ar.SessionID),
			zap.String("request_id", ar.ID),
			zap.Error(err),
		)
	}
	return nil
}

// parseSessionID extracts Session ID from HTTP request.
func (g *Gatekeeper) parseSessionID(r *http.Request, ar *requests.AuthorizationRequest) {
	if cookie, err := r.Cookie(g.sessionIDCookieName); err == nil {
		v, err := url.Parse(cookie.Value)
		if err == nil && v.String() != "" {
			ar.SessionID = util.SanitizeSessionID(v.String())
		}
	}
}

// handleUnauthorizedUser handles failed authorization requests.
func (g *Gatekeeper) handleUnauthorizedUser(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	err := ar.Response.Error
	g.logger.Debug(
		"token validation error",
		zap.String("session_id", ar.SessionID),
		zap.String("request_id", ar.ID),
		zap.Error(err),
	)

	switch {
	case (err == errors.ErrAccessNotAllowed) || (err == errors.ErrAccessNotAllowedByPathACL):
		return g.handleAuthorizeWithForbidden(w, r, ar)
	case (err == errors.ErrBasicAuthFailed) || (err == errors.ErrAPIKeyAuthFailed):
		return g.handleAuthorizeWithAuthFailed(w, r, ar)
	case err == errors.ErrCryptoKeyStoreTokenData:
		return g.handleAuthorizeWithBadRequest(w, r, ar)
	}

	g.expireAuthCookies(w, r)

	if !g.config.AuthRedirectDisabled {
		return g.handleAuthorizeWithRedirect(w, r, ar)
	}

	return err
}

// expireAuthCookies sends cookie delete in HTTP response.
func (g *Gatekeeper) expireAuthCookies(w http.ResponseWriter, r *http.Request) {
	cookies := g.tokenValidator.GetAuthCookies()
	if cookies == nil {
		return
	}

	for _, cookie := range r.Cookies() {
		if _, exists := cookies[cookie.Name]; !exists {
			continue
		}
		w.Header().Add("Set-Cookie", cookie.Name+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
	}
}

// handleAuthorizeWithAuthFailed handles failed authorization requests based on
// basic authentication and API keys.
func (g *Gatekeeper) handleAuthorizeWithAuthFailed(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	g.expireAuthCookies(w, r)
	w.WriteHeader(401)
	w.Write([]byte(`401 Unauthorized`))
	return ar.Response.Error
}

// handleAuthorizeWithBadRequest handles failed authorization requests where
// user data was insufficient to establish a user.
func (g *Gatekeeper) handleAuthorizeWithBadRequest(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	g.expireAuthCookies(w, r)
	w.WriteHeader(400)
	w.Write([]byte(`400 Bad Request`))
	return ar.Response.Error
}

// handleAuthorizeWithForbidden handles forbidden responses.
func (g *Gatekeeper) handleAuthorizeWithForbidden(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	if g.config.ForbiddenURL == "" {
		w.WriteHeader(403)
		w.Write([]byte(`Forbidden`))
		return ar.Response.Error
	}

	if strings.Contains(g.config.ForbiddenURL, "{") && strings.Contains(g.config.ForbiddenURL, "}") {
		redirectLocation, ok := getForbiddenRedirectLocation(g.config.ForbiddenURL, r)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`Forbidden`))
			return ar.Response.Error
		}
		w.Header().Set("Location", redirectLocation)
	} else {
		w.Header().Set("Location", g.config.ForbiddenURL)
	}
	w.WriteHeader(303)
	w.Write([]byte(`Forbidden`))
	return ar.Response.Error
}

func getForbiddenRedirectLocation(template string, r *http.Request) (string, bool) {
	currentURL := util.GetCurrentURL(r)
	requestURI := getRequestURI(r)
	redirectLocation := strings.NewReplacer(
		"{http.request.uri}", requestURI,
		"{uri}", requestURI,
		"{url}", currentURL,
	).Replace(template)

	hasLocalPlaceholder := strings.Contains(template, "{uri}") || strings.Contains(template, "{http.request.uri}")
	if !hasLocalPlaceholder {
		return redirectLocation, true
	}

	// A local URI placeholder must not create or replace the redirect authority
	// when combined with surrounding template bytes. Two distinct local marker
	// paths make the comparison independent of any attacker-selected request URI.
	skeletons := make([]string, 0, 2)
	for _, markerPath := range []string{"/authcrunch-uri-a", "/authcrunch-uri-b"} {
		skeleton := strings.NewReplacer(
			"{http.request.uri}", markerPath,
			"{uri}", markerPath,
			"{url}", currentURL,
		).Replace(template)
		skeletons = append(skeletons, skeleton)
	}
	first, ok := getRedirectAuthority(skeletons[0])
	if !ok {
		return "", false
	}
	second, ok := getRedirectAuthority(skeletons[1])
	if !ok || first != second {
		return "", false
	}
	actual, ok := getRedirectAuthority(redirectLocation)
	if !ok || first != actual {
		return "", false
	}
	return redirectLocation, true
}

type redirectAuthority struct {
	scheme string
	host   string
	user   string
}

func getRedirectAuthority(value string) (redirectAuthority, bool) {
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return redirectAuthority{}, false
	}
	normalized := strings.Trim(value, " ")
	normalized = strings.ReplaceAll(normalized, `\`, "/")
	if strings.HasPrefix(normalized, "///") {
		normalized = "//" + strings.TrimLeft(normalized, "/")
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Opaque != "" || (u.Scheme != "" && u.Host == "") {
		return redirectAuthority{}, false
	}
	var userInfo string
	if u.User != nil {
		userInfo = u.User.String()
	}
	return redirectAuthority{scheme: u.Scheme, host: u.Host, user: userInfo}, true
}

func getRequestURI(r *http.Request) string {
	u := url.URL{
		Path:       r.URL.Path,
		RawPath:    r.URL.RawPath,
		RawQuery:   r.URL.RawQuery,
		ForceQuery: r.URL.ForceQuery,
	}
	s := u.RequestURI()
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	// Keep both browser authority prefixes behind a local dot segment.
	// URL.RequestURI escapes path backslashes; enforce the local-URI boundary
	// explicitly on the completed value as well.
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) {
		s = "/." + s
	}
	return s
}

func (g *Gatekeeper) handleAuthorizeWithRedirect(w http.ResponseWriter, r *http.Request, ar *requests.AuthorizationRequest) error {
	if ar.Redirect.AuthURL == "" {
		ar.Redirect.AuthURL = g.config.AuthURLPath
	}

	ar.Redirect.QueryDisabled = g.config.AuthRedirectQueryDisabled
	ar.Redirect.QueryParameter = g.config.AuthRedirectQueryParameter
	if g.config.AuthRedirectStatusCode > 0 {
		ar.Redirect.StatusCode = g.config.AuthRedirectStatusCode
	}

	if len(g.config.LoginHintValidators) > 0 {
		g.handleLoginHint(r, ar)
	}

	if g.config.AdditionalScopes {
		g.handleAdditionalScopes(r, ar)
	}

	if g.config.RedirectWithJavascript {
		g.logger.Debug(
			"redirecting unauthorized user",
			zap.String("session_id", ar.SessionID),
			zap.String("request_id", ar.ID),
			zap.String("method", "js"),
		)
		handlers.HandleJavascriptRedirect(w, r, ar)
	} else {
		g.logger.Debug(
			"redirecting unauthorized user",
			zap.String("session_id", ar.SessionID),
			zap.String("request_id", ar.ID),
			zap.String("method", "location"),
		)
		handlers.HandleLocationHeaderRedirect(w, r, ar)
	}
	return ar.Response.Error
}

func (g *Gatekeeper) stripAuthToken(r *http.Request, usr *user.User) {
	if !g.config.StripTokenEnabled {
		return
	}
	switch usr.TokenSource {
	case "bearer", "header", "basicauth":
		stripAuthorizationToken(r.Header, usr)
	case "apiauth":
		r.Header.Del(g.config.APIKeyHeaderName)
	case "query":
		values := r.URL.Query()
		entries := values[usr.TokenName]
		for i, entry := range entries {
			if strings.TrimSpace(entry) != usr.Token {
				continue
			}
			values[usr.TokenName] = append(entries[:i], entries[i+1:]...)
			if len(values[usr.TokenName]) == 0 {
				values.Del(usr.TokenName)
			}
			break
		}
		r.URL.RawQuery = values.Encode()
		r.RequestURI = r.URL.RequestURI()
	case "cookie":
		if usr.TokenName == "" {
			return
		}

		if _, exists := r.Header["Cookie"]; !exists {
			return
		}

		for i, entry := range r.Header["Cookie"] {
			var updatedEntry []string
			var updateCookie bool
			for _, cookie := range strings.Split(entry, ";") {
				s := strings.TrimSpace(cookie)
				parsed, err := http.ParseCookie(s)
				if err == nil && len(parsed) == 1 && parsed[0].Name == usr.TokenName && (parsed[0].Value == usr.Token || strings.HasPrefix(parsed[0].Value, usr.Token+" ")) {
					// Skip only the cookie which supplied the accepted token.
					updateCookie = true
					continue
				}
				updatedEntry = append(updatedEntry, cookie)
			}
			if !updateCookie {
				continue
			}
			r.Header["Cookie"][i] = strings.Join(updatedEntry, ";")
		}
	}
}

func stripAuthorizationToken(header http.Header, usr *user.User) {
	values := header.Values("Authorization")
	if len(values) == 0 {
		return
	}
	keptValues := make([]string, 0, len(values))
	for _, value := range values {
		entries := splitAuthorizationEntries(value)
		keptEntries := make([]string, 0, len(entries))
		removed := false
		for _, entry := range entries {
			trimmed := strings.TrimSpace(entry)
			remove := false
			switch usr.TokenSource {
			case "basicauth":
				parts := strings.Fields(trimmed)
				remove = len(parts) == 2 && strings.EqualFold(parts[0], "Basic")
			case "bearer":
				parts := strings.Fields(trimmed)
				remove = len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] == usr.Token
			case "header":
				name, value, found := strings.Cut(trimmed, "=")
				remove = found && strings.TrimSpace(name) == usr.TokenName && strings.TrimSpace(value) == usr.Token
			}
			if remove {
				removed = true
				continue
			}
			keptEntries = append(keptEntries, trimmed)
		}
		if !removed {
			keptValues = append(keptValues, value)
		} else if len(keptEntries) > 0 {
			keptValues = append(keptValues, strings.Join(keptEntries, ", "))
		}
	}
	header.Del("Authorization")
	for _, value := range keptValues {
		header.Add("Authorization", value)
	}
}

// splitAuthorizationEntries supports the repository's comma-separated
// credential extension without treating commas inside quoted auth parameters
// as credential boundaries. An unterminated quote keeps the remainder in one
// entry, so malformed input cannot expose a hidden credential.
func splitAuthorizationEntries(value string) []string {
	var entries []string
	start := 0
	quoted := false
	escaped := false
	for i := 0; i < len(value); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case value[i] == ',' && !quoted:
			entries = append(entries, value[start:i])
			start = i + 1
		}
	}
	return append(entries, value[start:])
}

func (g *Gatekeeper) injectHeaders(r *http.Request, usr *user.User) {
	g.stripInjectedHeaders(r)
	if g.config.PassClaimsWithHeaders {
		// Inject default X-Token headers.
		headers := usr.GetRequestHeaders()
		if headers == nil {
			headers = make(map[string]string)
			if usr.Claims.Name != "" {
				headers[claimHeaderUserName] = usr.Claims.Name
			}
			if usr.Claims.Email != "" {
				headers[claimHeaderUserEmail] = usr.Claims.Email
			}
			if len(usr.Claims.Roles) > 0 {
				headers[claimHeaderUserRoles] = strings.Join(usr.Claims.Roles, " ")
			}
			if usr.Claims.Subject != "" {
				headers[claimHeaderSubject] = usr.Claims.Subject
			}
			usr.SetRequestHeaders(headers)
		}

		for k, v := range headers {
			if g.injectedHeaders != nil {
				if _, exists := g.injectedHeaders[http.CanonicalHeaderKey(k)]; exists {
					continue
				}
			}
			r.Header.Set(k, v)
		}
	}

	// Inject custom headers.
	for _, entry := range g.config.HeaderInjectionConfigs {
		if v := usr.GetClaimValueByField(entry.Field); v != "" {
			r.Header.Set(entry.Header, v)
		}
	}
}

func (g *Gatekeeper) stripInjectedHeaders(r *http.Request) {
	if g.config.PassClaimsWithHeaders {
		for _, name := range [...]string{
			claimHeaderUserName,
			claimHeaderUserEmail,
			claimHeaderUserRoles,
			claimHeaderSubject,
		} {
			r.Header.Del(name)
		}
	}
	for _, entry := range g.config.HeaderInjectionConfigs {
		r.Header.Del(entry.Header)
	}
}

func (g *Gatekeeper) handleLoginHint(r *http.Request, ar *requests.AuthorizationRequest) {
	if loginHint := r.URL.Query().Get("login_hint"); loginHint != "" {
		if err := validate.LoginHint(loginHint, g.config.LoginHintValidators); err != nil {
			g.logger.Warn(err.Error())
		} else {
			ar.Redirect.LoginHint = loginHint
		}
	}
}

func (g *Gatekeeper) handleAdditionalScopes(r *http.Request, ar *requests.AuthorizationRequest) {
	if additionalScopes := r.URL.Query().Get("additional_scopes"); additionalScopes != "" {
		if err := validate.AdditionalScopes(additionalScopes); err != nil {
			g.logger.Warn("Provide a valid set of additional scopes in the query parameter (ex.: scope_A scopeB)",
				zap.String("additional_scopes", additionalScopes),
				zap.Error(err),
			)
		} else {
			ar.Redirect.AdditionalScopes = additionalScopes
		}
	}

}
