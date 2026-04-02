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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/translate"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func getEndpoint(p, s string) (string, error) {
	i := strings.Index(p, s)
	if i < 0 {
		return s, fmt.Errorf("%s is not in %s", p, s)
	}
	return strings.TrimPrefix(p[i:], s), nil
}

func (p *Portal) handleHTTPPortal(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	if parsedUser == nil {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	usr, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.deleteAuthCookies(w, r)
		p.logger.Debug(
			"User session not found, redirect to login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", parsedUser.Claims),
			zap.Error(err),
		)
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	return p.handleHTTPPortalScreen(ctx, w, r, rr, usr)
}

func (p *Portal) handleHTTPPortalScreen(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	if cookie, err := r.Cookie(p.cookie.RefererCookieName); err == nil {
		redirectURL, err := url.Parse(cookie.Value)
		if err == nil {
			if len(p.config.TrustedLoginRedirectURIConfigs) > 0 && redirects.Match(redirectURL, p.config.TrustedLoginRedirectURIConfigs) {
				p.logger.Debug(
					"Cookie-based redirect",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("redirect_url", redirectURL.String()),
				)
				w.Header().Set("Location", redirectURL.String())
				cookie.Value = ""
				cookie.MaxAge = -1
				cookie.Expires = time.Unix(0, 0)
				http.SetCookie(w, cookie)
				w.Header().Add("Set-Cookie", p.cookie.GetDeleteRefererCookie(rr.Upstream.BasePath))
				w.WriteHeader(http.StatusSeeOther)
				return nil
			}
			p.logger.Warn(
				"Redirect cookie value is not trusted, ignoring",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("redirect_url", redirectURL.String()),
			)
		}
		cookie.Value = ""
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, cookie)
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteRefererCookie(rr.Upstream.BasePath))
	}
	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	resp.PageTitle = translate.Translate("applications_label", p.ui.Language, nil)
	if len(usr.FrontendLinks) > 0 {
		// Add additional frontend links.
		resp.AddFrontendLinks(usr.FrontendLinks)
	}
	resp.Data["i18n_access_services_instruction"] = translate.Translate("access_services_instruction", p.ui.Language, nil)
	resp.Data["i18n_sign_out"] = translate.Translate("sign_out", p.ui.Language, nil)
	content, err := p.ui.Render("portal", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}
