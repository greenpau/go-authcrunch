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
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

type realmQuery struct {
	Query string `json:"query"`
}

type realmEntry struct {
	Realm string `json:"realm"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

func (p *Portal) handleAPIListRealms(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, _ *user.User) error {
	w.Header().Set("Content-Type", "application/json")

	reqQuery := &realmQuery{}
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(reqQuery); err != nil {
			p.logger.Error(
				"failed to decode request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/realms"),
				zap.String("error", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		}
	}

	resp := make(map[string]any)
	resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

	realms := []realmEntry{}
	for _, ids := range p.identityStores {
		if reqQuery.Query == "all" {
			realms = append(realms, realmEntry{
				Realm: ids.GetRealm(),
				Name:  ids.GetName(),
				Kind:  ids.GetKind(),
			})
			continue
		}
		if strings.Contains(ids.GetRealm(), reqQuery.Query) {
			realms = append(realms, realmEntry{
				Realm: ids.GetRealm(),
				Name:  ids.GetName(),
				Kind:  ids.GetKind(),
			})
		}
	}
	resp["realms"] = realms
	resp["count"] = len(realms)

	respBytes, err := json.Marshal(resp)
	if err != nil {
		p.logger.Error(
			"failed to encode response",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/realms"),
			zap.String("error", err.Error()),
		)
		return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
	return nil
}
