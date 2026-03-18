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
	"net/url"

	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

func (p *Portal) injectRedirectURL(_ context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if r.Method == "GET" {
		q := r.URL.Query()
		if redirectURL, exists := q["redirect_url"]; exists {
			if len(p.config.TrustedLoginRedirectURIConfigs) < 1 {
				p.logger.Debug(
					"trust login redirect uri is not configured, but detected redirect_url attempt",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return
			}

			if len(redirectURL) < 1 {
				p.logger.Debug(
					"unexpected redirect_url format",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return
			}

			loginRedirectURL, err := url.Parse(redirectURL[0])
			if err != nil {
				p.logger.Debug(
					"failed to parse provided redirect_url",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return
			}

			if !redirects.Match(loginRedirectURL, p.config.TrustedLoginRedirectURIConfigs) {
				p.logger.Debug(
					"provided redirect_url is not trusted",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
				)
				return
			}

			c := p.cookie.GetCookie(addrutil.GetSourceHost(r), p.cookie.RefererCookieName, util.StripQueryParam(redirectURL[0], "login_hint"))
			p.logger.Debug(
				"redirect recorded",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("redirect_url", c),
				zap.Any("redirect_url_any", redirectURL),
			)
			w.Header().Add("Set-Cookie", c)
			rr.Response.RedirectURL = c
		}
	}
}
