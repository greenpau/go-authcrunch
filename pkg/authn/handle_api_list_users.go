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
	"encoding/json"

	// "github.com/greenpau/go-authcrunch/pkg/identity"
	"net/http"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

type listUsersRequest struct {
	Query string `json:"query"`
	Realm string `json:"realm"`
}

type listUsersResponse struct {
	Count     int              `json:"count"`
	Users     []map[string]any `json:"users"`
	Timestamp string           `json:"timestamp"`
}

func (p *Portal) handleAPIListUsers(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, _ *user.User) error {
	req := &listUsersRequest{}
	if status, err := decodeAdminAPIRequest(w, r, req); err != nil {
		p.logger.Error(
			"failed to decode request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/users"),
			zap.String("error", err.Error()),
		)
		return p.handleJSONError(ctx, w, status, http.StatusText(status))
	}

	if req.Realm == "" {
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/users"),
			zap.String("error", "missing realm"),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	users := []map[string]any{}
	for _, ids := range p.identityStores {
		if ids.GetRealm() != req.Realm {
			continue
		}
		var err error
		users, err = ids.GetUsersMetadata(req.Query)
		if err != nil {
			p.logger.Warn(
				"failed to fetch users metadata",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/users"),
				zap.Error(err),
			)
			return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		}
		break
	}

	resp := listUsersResponse{
		Count:     len(users),
		Users:     users,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		p.logger.Error(
			"failed to encode response",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/users"),
			zap.String("error", err.Error()),
		)
		return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
	return nil
}
