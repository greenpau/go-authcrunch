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
	"github.com/greenpau/aaasf/pkg/authz/bypass"
	"github.com/greenpau/aaasf/pkg/authz/handlers"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/aaasf/pkg/requests"
	"github.com/greenpau/aaasf/pkg/user"
	"github.com/greenpau/aaasf/pkg/util"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
)

var (
	placeholders = []string{
		"http.request.uri", "uri",
		"url",
	}
)

// Authenticate authorizes HTTP requests.
func (g *Gatekeeper) Authenticate(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) error {
	// rr.Response.User       = map[string]interface{}
	// rr.Response.Authorized = bool
	// rr.Response.Error      = error

	// Perform authorization bypass checks
	if g.bypassEnabled && bypass.Match(r, g.config.BypassConfigs) {
		rr.Response.Authorized = false
		return nil
	}

	g.parseSessionID(r, rr)

	usr, err := g.tokenValidator.Authorize(context.Background(), r)
	if err != nil {
		rr.Response.Error = err
		return g.handleAuthorizeWithError(w, r, rr, usr)
	}

	return g.handleAuthorizedUser(w, r, rr, usr)
}

// handleAuthorizedUser handles authorized requests.
func (g *Gatekeeper) handleAuthorizedUser(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest, usr *user.User) error {
	g.injectHeaders(r, usr)
	g.stripAuthToken(r, usr)

	rr.Response.Authorized = true

	if usr.Cached {
		rr.Response.User = usr.GetRequestIdentity()
		return nil
	}

	rr.Response.User = usr.BuildRequestIdentity(g.config.UserIdentityField)

	if err := g.tokenValidator.CacheUser(usr); err != nil {
		g.logger.Error(
			"token caching error",
			zap.String("session_id", rr.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
	}
	return nil
}

// parseSessionID extracts Session ID from HTTP request.
func (g *Gatekeeper) parseSessionID(r *http.Request, rr *requests.AuthorizationRequest) {
	if cookie, err := r.Cookie("AUTHP_SESSION_ID"); err == nil {
		v, err := url.Parse(cookie.Value)
		if err == nil && v.String() != "" {
			rr.SessionID = v.String()
		}
	}
}

// handleAuthorizeWithError handles failed authorization requests.
func (g *Gatekeeper) handleAuthorizeWithError(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest, usr *user.User) error {
	err := rr.Response.Error
	g.logger.Debug(
		"token validation error",
		zap.String("session_id", rr.SessionID),
		zap.String("request_id", rr.ID),
		zap.Error(err),
	)

	switch {
	case strings.Contains(err.Error(), "user role is valid, but not allowed by"):
		return g.handleAuthorizeWithForbidden(w, r, rr)
	case (err == errors.ErrBasicAuthFailed) || (err == errors.ErrAPIKeyAuthFailed):
		return g.handleAuthorizeWithAuthFailed(w, r, rr)
	}

	g.expireAuthCookies(w, r)

	if !g.config.AuthRedirectDisabled {
		return g.handleAuthorizeWithRedirect(w, r, rr, usr)
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
	return
}

// handleAuthorizeWithAuthFailed handles failed authorization requests based on
// basic authentication and API keys.
func (g *Gatekeeper) handleAuthorizeWithAuthFailed(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) error {
	g.expireAuthCookies(w, r)
	w.WriteHeader(401)
	w.Write([]byte(`401 Unauthorized`))
	return rr.Response.Error
}

// handleAuthorizeWithForbidden handles forbidden responses.
func (g *Gatekeeper) handleAuthorizeWithForbidden(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) error {
	if g.config.ForbiddenURL == "" {
		w.WriteHeader(403)
		w.Write([]byte(`Forbidden`))
		return rr.Response.Error
	}

	if strings.Contains(g.config.ForbiddenURL, "{") && strings.Contains(g.config.ForbiddenURL, "}") {
		// Run through placeholder replacer.
		redirectLocation := g.config.ForbiddenURL
		for _, placeholder := range placeholders {
			switch placeholder {
			case "uri", "http.request.uri":
				redirectLocation = strings.ReplaceAll(redirectLocation, "{"+placeholder+"}", r.URL.String())
			case "url":
				redirectLocation = strings.ReplaceAll(redirectLocation, "{"+placeholder+"}", util.GetCurrentURL(r))
			}
		}
		w.Header().Set("Location", redirectLocation)
	} else {
		w.Header().Set("Location", g.config.ForbiddenURL)
	}
	w.WriteHeader(303)
	w.Write([]byte(`Forbidden`))
	return rr.Response.Error
}

func (g *Gatekeeper) handleAuthorizeWithRedirect(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest, usr *user.User) error {
	if usr != nil {
		// If the issuer URL contains callback URL, then redirect to it.
		if usr.Authenticator.URL != "" && strings.HasPrefix(usr.Authenticator.URL, "http") {
			usr.Authenticator.URL = strings.TrimSuffix(usr.Authenticator.URL, "authorization-code-callback")
			rr.Redirect.AuthURL = usr.Authenticator.URL
		}
	}
	if rr.Redirect.AuthURL != "" {
		rr.Redirect.AuthURL = g.config.AuthURLPath
	}
	rr.Redirect.QueryDisabled = g.config.AuthRedirectQueryDisabled
	rr.Redirect.QueryParameter = g.config.AuthRedirectQueryParameter
	if g.config.AuthRedirectStatusCode > 0 {
		rr.Redirect.StatusCode = g.config.AuthRedirectStatusCode
	}

	if g.config.RedirectWithJavascript {
		g.logger.Debug(
			"redirecting unauthorized user",
			zap.String("session_id", rr.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("method", "js"),
		)
		handlers.HandleJavascriptRedirect(w, r, rr)
	} else {
		g.logger.Debug(
			"redirecting unauthorized user",
			zap.String("session_id", rr.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("method", "location"),
		)
		handlers.HandleLocationHeaderRedirect(w, r, rr)
	}
	return rr.Response.Error
}

func (g *Gatekeeper) stripAuthToken(r *http.Request, usr *user.User) {
	if !g.config.StripTokenEnabled {
		return
	}
	switch usr.TokenSource {
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
				if strings.HasPrefix(s, usr.TokenName+"=") {
					// Skip the cookie matching the token name.
					updateCookie = true
					continue
				}
				if strings.Contains(s, usr.Token) {
					// Skip the cookie with the value matching user token.
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

func (g *Gatekeeper) injectHeaders(r *http.Request, usr *user.User) {
	if g.config.PassClaimsWithHeaders {
		// Inject default X-Token headers.
		headers := usr.GetRequestHeaders()
		if headers == nil {
			headers = make(map[string]string)
			if usr.Claims.Name != "" {
				headers["X-Token-User-Name"] = usr.Claims.Name
			}
			if usr.Claims.Email != "" {
				headers["X-Token-User-Email"] = usr.Claims.Email
			}
			if len(usr.Claims.Roles) > 0 {
				headers["X-Token-User-Roles"] = strings.Join(usr.Claims.Roles, " ")
			}
			if usr.Claims.Subject != "" {
				headers["X-Token-Subject"] = usr.Claims.Subject
			}
			usr.SetRequestHeaders(headers)
		}

		for k, v := range headers {
			if g.injectedHeaders != nil {
				if _, exists := g.injectedHeaders[k]; exists {
					continue
				}
			}
			r.Header.Set(k, v)
		}
	}

	if g.injectedHeaders != nil {
		// Inject custom headers.
		for _, entry := range g.config.HeaderInjectionConfigs {
			if v := usr.GetClaimValueByField(entry.Field); v != "" {
				r.Header.Set(entry.Header, v)
			}
		}
	}
}
