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

type realmReloadRequest struct {
	Realm string `json:"realm"`
}

func (p *Portal) handleAPIReloadRealm(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, _ *user.User) error {
	req := &realmReloadRequest{}
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			p.logger.Error(
				"failed to decode request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/reload"),
				zap.String("error", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		}
	}

	if req.Realm == "" {
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/reload"),
			zap.String("error", "missing realm"),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	metadata := map[string]any{}
	for _, ids := range p.identityStores {
		if ids.GetRealm() != req.Realm {
			continue
		}
		var err error
		err = ids.Reload()
		if err != nil {
			p.logger.Warn(
				"failed to reaload database",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/reload"),
				zap.Error(err),
			)
			metadata["status"] = "failure"
		} else {
			metadata["status"] = "success"
		}

		p.logger.Info(
			"reloaded realm",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/reload"),
			zap.String("realm", req.Realm),
		)
		break
	}

	metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

	respBytes, err := json.Marshal(metadata)
	if err != nil {
		p.logger.Error(
			"failed to encode response",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/reload"),
			zap.String("error", err.Error()),
		)
		return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
	return nil
}
