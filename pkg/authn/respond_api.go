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

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

func (p *Portal) handleAPI(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	p.injectSessionID(ctx, w, r, rr)

	p.logger.Debug(
		"Received API request",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("url_base_path", rr.Upstream.BasePath),
		zap.String("src_ip", addrutil.GetSourceAddress(r)),
		zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
	)

	usr, err := p.authorizeRequest(ctx, w, r, rr)
	if err != nil {
		p.logger.Debug(
			"API authorization failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/refresh_token"):
		return p.handleAPIRefreshToken(ctx, w, r, rr, usr)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/system"):
		return p.handleAPISystem(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/server/realms"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/realms"),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPIListRealms(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/server/users"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/users"),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPIListUsers(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/server/user"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/user"),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPICrudUser(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/server/info"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/info"),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPIRealmInfo(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/server/reload"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/reload"),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPIReloadRealm(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/server/metadata"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/metadata"),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPIMetadata(ctx, w, r, rr, usr)
	case p.config.API.ProfileEnabled && r.Method == "POST" && strings.Contains(r.URL.Path, "/api/profile"):
		if err := p.authorizedRole(usr, []role.Kind{role.Admin, role.User}, rr.Response.Authenticated); err != nil {
			p.logger.Debug(
				"User is not authorized accessing API",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("reason", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		return p.handleAPIProfile(ctx, w, r, rr, usr)
	default:
		p.logger.Debug(
			"API endpoint is not available",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("api_config", p.config.API),
			zap.String("endpoint_path", r.URL.Path),
			zap.String("endpoint_method", r.Method),
		)
	}

	return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
}
