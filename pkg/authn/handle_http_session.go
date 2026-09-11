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

package authn

import (
	"context"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func (p *Portal) hasRefreshCookie(r *http.Request) bool {
	return p.refresh != nil && len(r.CookiesNamed(p.config.RefreshTokens.CookieName)) > 0
}

func (p *Portal) handleSessionPage(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, action string) error {
	if r.Method != http.MethodGet || p.validateRefreshOrigin(r) != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}
	p.disableClientCache(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	resp := p.ui.GetArgs()
	resp.BaseURL(p.config.RefreshTokens.BasePath)
	resp.Data["session_action"] = action
	resp.PageTitle, resp.Message = "Continue your session", "Checking your session…"
	if action == "logout" {
		resp.PageTitle, resp.Message = "Sign out", "Sign out of this browser session?"
		next := strings.TrimSuffix(p.config.RefreshTokens.BasePath, "/") + "/login"
		if target := redirects.GetRedirectURI(r.URL); target != nil && redirects.Match(target, p.config.TrustedLogoutRedirectURIConfigs) {
			next = target.String()
		}
		resp.Data["session_next"] = next
	}
	content, err := p.ui.Render("session", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}
