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
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

// FetchUserDashboardData fetches user dashboard information.
func (p *Portal) FetchUserDashboardData(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]any,
	usr *user.User,
	backend ids.IdentityStore) error {

	// Data Buckets
	entry := make(map[string]any)
	assetCount := make(map[string]any)

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
		return profileBackendError(w, rr, resp, err, http.StatusInternalServerError)
	}
	user := rr.Response.Payload.(*identity.User)
	entry["metadata"] = profileMetadata(user)

	// Query only implemented collections. Missing counts mean unsupported,
	// never zero. Each supported query still rechecks the immutable proof.
	caps := identity.StoreCapabilities{APIKeys: true, PublicKeys: true, MFA: true}
	if declared, ok := profileStoreCapabilities(backend); ok {
		caps = declared
		entry["capabilities"] = caps
	}
	if caps.APIKeys {
		rr.Key.Usage, rr.Key.IncludeAll = "api", true
		if err := backend.Request(operator.GetAPIKeys, rr); err != nil {
			return profileBackendError(w, rr, resp, err, http.StatusInternalServerError)
		}
		assetCount["api_key"] = rr.Response.Payload.(*identity.APIKeyBundle).Size()
	}
	if caps.PublicKeys {
		for _, usage := range []string{"ssh", "gpg"} {
			rr.Key.Usage, rr.Key.IncludeAll = usage, true
			if err := backend.Request(operator.GetPublicKeys, rr); err != nil {
				return profileBackendError(w, rr, resp, err, http.StatusInternalServerError)
			}
			assetCount[usage+"_key"] = len(rr.Response.Payload.(*identity.PublicKeyBundle).Get())
		}
	}
	if caps.MFA {
		rr.MfaToken.IncludeAll = true
		if err := backend.Request(operator.GetMfaTokens, rr); err != nil {
			return profileBackendError(w, rr, resp, err, http.StatusInternalServerError)
		}
		assetCount["mfa_2fa"] = len(rr.Response.Payload.(*identity.MfaTokenBundle).Get())
	}

	// User Roles

	entry["roles"] = parsedUser.Claims.Roles

	// Finalize

	entry["asset_count"] = assetCount
	// Retain the legacy reserved field only for the legacy store. It is not
	// evidence that external-account self-service has been implemented.
	if backend.GetKind() == "local" {
		entry["connected_accounts"] = []any{}
	}
	resp["entry"] = entry
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
