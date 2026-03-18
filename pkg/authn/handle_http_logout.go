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
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

func (p *Portal) deleteAuthCookies(w http.ResponseWriter, r *http.Request) {
	for tokenName := range p.validator.GetAuthCookies() {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(addrutil.GetSourceHost(r), tokenName))
	}
}

func (p *Portal) handleHTTPLogout(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	h := addrutil.GetSourceHost(r)
	for tokenName := range p.validator.GetAuthCookies() {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(h, tokenName))
	}
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteRefreshTokenCookie())
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(h, p.cookie.RefererCookieName))
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(h, p.cookie.SessionIDCookieName))

	if parsedUser != nil && parsedUser.Claims != nil {
		p.logger.Debug(
			"user logout",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", parsedUser.Claims),
		)
		if strings.Contains(parsedUser.Claims.Issuer, "/oauth2/") {
			return p.handleHTTPRedirect(ctx, w, r, rr, extractRealmLogout(parsedUser.Claims.Issuer, "oauth2"))
		}
	} else {
		p.logger.Debug(
			"user logout",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
		)
	}

	// Find whether there is redirect_uri in Query. OAuth users take the early return above.
	if redirects.HasRedirectURI(r.URL) && (len(p.config.TrustedLogoutRedirectURIConfigs) > 0) {
		p.logger.Debug(
			"user logout with redirect",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
		)
		redirectURI := redirects.GetRedirectURI(r.URL)
		if redirectURI != nil {
			if redirects.Match(redirectURI, p.config.TrustedLogoutRedirectURIConfigs) {
				p.logger.Debug(
					"found trusted logout redirect uri",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("redirect_uri", redirects.GetRawRedirectURI(r.URL)),
				)
				return p.handleHTTPRedirectExternal(ctx, w, r, rr, redirects.GetRawRedirectURI(r.URL))
			}
		}
	}

	return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
}

func extractRealmLogout(s, sp string) string {
	var ready bool
	for _, k := range strings.Split(s, "/") {
		if k == sp {
			ready = true
			continue
		}
		if ready {
			return "/" + strings.Join([]string{sp, k, "logout"}, "/")
		}
	}
	return "/logout"
}
