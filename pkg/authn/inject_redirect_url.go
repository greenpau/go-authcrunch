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

package authn

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"go.uber.org/zap"
)

func (p *Portal) injectRedirectURL(_ context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if redirectCookie := p.recordRedirectURL(w, r, rr); redirectCookie != "" {
		rr.Response.RedirectURL = redirectCookie
	}
}

// loginReturnURL returns the trusted post-login destination carried in the
// request's redirect_url query parameter, or an empty string. Unlike the shared
// redirect cookie, it belongs to the one login flow whose URL carries it.
func (p *Portal) loginReturnURL(r *http.Request, rr *requests.Request) string {
	values := r.URL.Query()["redirect_url"]
	if len(values) < 1 {
		return ""
	}
	returnURL := p.trustedLoginReturnURL(values[0])
	if returnURL == "" {
		p.logger.Debug(
			"login flow destination is not trusted, ignoring",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
		)
	}
	return returnURL
}

// errLoginElsewhereNotAdmitted reports that the login page's probe carries a
// valid token which this portal does not admit.
var errLoginElsewhereNotAdmitted = errors.New("login elsewhere is not admitted by the portal")

// isLoginElsewhereProbe reports whether r is the login page asking whoami
// whether another tab has signed the browser in.
func isLoginElsewhereProbe(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/whoami") && r.URL.Query().Get("probe") == "login"
}

// loginPageLocation returns the portal-relative login page location, carrying
// the tab's own trusted destination and fresh-login state when it has them.
func loginPageLocation(returnURL string, fresh bool) string {
	query := url.Values{}
	if fresh {
		query.Set("fresh", "1")
	}
	if returnURL != "" {
		query.Set("redirect_url", returnURL)
	}
	if len(query) == 0 {
		return "/login"
	}
	return "/login?" + query.Encode()
}

// hasPortalSession reports whether usr holds this portal's session, which the
// portal pages require of a signed-in browser.
func (p *Portal) hasPortalSession(usr *user.User) bool {
	_, err := p.sessions.Get(usr.Claims.ID)
	return err == nil
}

// returnToLoginDestination sends a signed-in tab to the destination its own
// login flow carries.
func (p *Portal) returnToLoginDestination(w http.ResponseWriter, r *http.Request, rr *requests.Request, returnURL string) error {
	p.consumeOwnRedirectCookie(w, r, rr, returnURL)
	p.disableClientCache(w)
	w.Header().Set("Location", returnURL)
	w.WriteHeader(http.StatusSeeOther)
	return nil
}

// consumeOwnRedirectCookie deletes the shared redirect cookie when it holds the
// destination this login flow returns to by itself, which no other request would
// then consume. A cookie holding another tab's destination is left in place.
func (p *Portal) consumeOwnRedirectCookie(w http.ResponseWriter, r *http.Request, rr *requests.Request, returnURL string) {
	if cookie, err := r.Cookie(p.cookie.RefererCookieName); err == nil && p.trustedLoginReturnURL(cookie.Value) == returnURL {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteRefererCookie(rr.Upstream.BasePath))
	}
}

// maxLoginReturnURLLength bounds a destination carried by a login flow, which
// the portal keeps for the life of that login; a longer one is left to the
// redirect cookie, which the browser holds.
const maxLoginReturnURLLength = 2048

// trustedLoginReturnURL returns the trusted destination a login flow carries
// itself, or an empty string. The bound applies to the value as returned,
// which re-encoding can lengthen.
func (p *Portal) trustedLoginReturnURL(raw string) string {
	if len(raw) > maxLoginReturnURLLength {
		return ""
	}
	if returnURL := p.trustedLoginRedirectURL(raw); len(returnURL) <= maxLoginReturnURLLength {
		return returnURL
	}
	return ""
}

// trustedLoginRedirectURL applies the trusted login redirect rules to an
// absolute HTTP(S) destination, returning it without its login hint, or an
// empty string. The login flows and the redirect cookie share these rules.
func (p *Portal) trustedLoginRedirectURL(raw string) string {
	if raw == "" || len(p.config.TrustedLoginRedirectURIConfigs) < 1 {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return ""
	}
	if !redirects.Match(parsed, p.config.TrustedLoginRedirectURIConfigs) {
		return ""
	}
	return util.StripQueryParam(raw, "login_hint")
}

// recordRedirectURL persists a trusted post-login destination without assigning
// it to the response field used by identity providers for their authorization
// endpoint.
func (p *Portal) recordRedirectURL(w http.ResponseWriter, r *http.Request, rr *requests.Request) string {
	if r.Method == "GET" {
		q := r.URL.Query()
		if redirectURL, exists := q["redirect_url"]; exists {
			if len(p.config.TrustedLoginRedirectURIConfigs) < 1 {
				p.logger.Debug(
					"trust login redirect uri is not configured, but detected redirect_url attempt",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return ""
			}

			if len(redirectURL) < 1 {
				p.logger.Debug(
					"unexpected redirect_url format",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return ""
			}

			loginRedirectURL := p.trustedLoginRedirectURL(redirectURL[0])
			if loginRedirectURL == "" {
				p.logger.Debug(
					"provided redirect_url is not trusted",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return ""
			}

			c := p.cookie.GetRefererCookie(rr.Upstream.BasePath, loginRedirectURL)
			p.logger.Debug(
				"redirect recorded",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("redirect_url", c),
				zap.Any("redirect_url_any", redirectURL),
			)
			w.Header().Add("Set-Cookie", c)
			return c
		}
	}
	return ""
}
