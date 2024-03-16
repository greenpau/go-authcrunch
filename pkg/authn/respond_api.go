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
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Portal) handleAPI(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	p.injectSessionID(ctx, w, r, rr)
	w.Header().Set("Content-Type", "application/json")
	p.logger.Debug(
		"Received API request",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("url_path", r.URL.Path),
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

	if !rr.Response.Authenticated {
		p.logger.Debug(
			"User is not authorized to use API",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
		)
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}

	if !usr.HasRole("authp/admin") {
		p.logger.Debug(
			"API is not available because user has no admin privileges",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
		)
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusForbidden, http.StatusText(http.StatusForbidden))
	}

	if p.config.API == nil || (p.config.API != nil && !p.config.API.ProfileEnabled && !p.config.API.AdminEnabled) {
		p.logger.Debug(
			"API is not available",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("api_config", p.config.API),
		)
		return p.handleJSONError(ctx, w, http.StatusNotImplemented, http.StatusText(http.StatusNotImplemented))
	}

	switch {
	case p.config.API.AdminEnabled && strings.HasSuffix(r.URL.Path, "/api/metadata"):
		return p.handleAPIMetadata(ctx, w, r, rr, usr)
	case p.config.API.AdminEnabled && strings.Contains(r.URL.Path, "/api/orgs"):
		return p.handleJSONError(ctx, w, http.StatusNotImplemented, http.StatusText(http.StatusNotImplemented))
	case p.config.API.AdminEnabled && strings.Contains(r.URL.Path, "/api/teams"):
		return p.handleJSONError(ctx, w, http.StatusNotImplemented, http.StatusText(http.StatusNotImplemented))
	case p.config.API.AdminEnabled && strings.Contains(r.URL.Path, "/api/users"):
		return p.handleAPIListUsers(ctx, w, r, rr, usr)
	case p.config.API.ProfileEnabled && r.Method == "POST" && strings.Contains(r.URL.Path, "/api/profile"):
		return p.handleAPIProfile(ctx, w, r, rr, usr)
	default:
		p.logger.Debug(
			"API endpoint is not supported",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("api_config", p.config.API),
			zap.String("endpoint_path", r.URL.Path),
			zap.String("endpoint_method", r.Method),
		)
	}

	return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
}
