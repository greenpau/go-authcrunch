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
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
	"net/http"
)

func (p *Portal) handleHTTPAppsMobileAccess(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)

	if parsedUser == nil {
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	_, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.deleteAuthCookies(w, r)
		p.logger.Debug(
			"User session not found, redirect to login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", parsedUser.Claims),
			zap.Error(err),
		)
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	resp := p.ui.GetArgs()
	resp.PageTitle = "Mobile Access"
	resp.BaseURL(rr.Upstream.BasePath)

	content, err := p.ui.Render("apps_mobile_access", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}
