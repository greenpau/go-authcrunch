// Copyright 2024 Paul Greenberg greenpau@outlook.com
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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

// FetchUserInfo fetches user identity information.
func (p *Portal) FetchUserInfo(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore) error {

	// Data Buckets
	entry := make(map[string]interface{})

	// General Info
	err := backend.Request(operator.GetUser, rr)
	if err != nil {
		resp["message"] = "failed to extract user metadata"
		p.logger.Debug(
			"failed to extract user metadata",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	user := rr.Response.Payload.(*identity.User)
	entry["metadata"] = user.GetMetadata()

	// User Roles

	entry["roles"] = parsedUser.Claims.Roles

	// Token

	tokenMap := make(map[string]interface{})
	for k, v := range usr.AsMap() {
		tokenMap[k] = v
	}
	tokenMap["authenticated"] = true
	if usr.Claims.ExpiresAt > 0 {
		tokenMap["expires_at_utc"] = time.Unix(usr.Claims.ExpiresAt, 0).Format(time.UnixDate)
	}
	if usr.Claims.IssuedAt > 0 {
		tokenMap["issued_at_utc"] = time.Unix(usr.Claims.IssuedAt, 0).Format(time.UnixDate)
	}
	if usr.Claims.NotBefore > 0 {
		tokenMap["not_before_utc"] = time.Unix(usr.Claims.NotBefore, 0).Format(time.UnixDate)
	}
	prettyTokenMap, err := json.MarshalIndent(tokenMap, "", "  ")
	if err != nil {
		p.logger.Debug(
			"failed to prettify user token",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	entry["token"] = string(prettyTokenMap)

	// Finalize

	resp["entry"] = entry
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
