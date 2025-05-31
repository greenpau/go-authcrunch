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
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore) error {

	// Data Buckets
	entry := make(map[string]interface{})
	assetCount := make(map[string]interface{})

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

	// API Keys
	rr.Key.Usage = "api"
	rr.Key.IncludeAll = true
	err = backend.Request(operator.GetAPIKeys, rr)
	if err != nil {
		resp["message"] = "failed to extract user api keys"
		p.logger.Debug(
			"failed to extract user api keys",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	apiKeysBundle := rr.Response.Payload.(*identity.APIKeyBundle)
	apiKeys := apiKeysBundle.Get()
	assetCount["api_key"] = len(apiKeys)

	// SSH Keys
	rr.Key.Usage = "ssh"
	rr.Key.IncludeAll = true
	err = backend.Request(operator.GetPublicKeys, rr)
	if err != nil {
		resp["message"] = "failed to extract user ssh keys"
		p.logger.Debug(
			"failed to extract user api keys",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	sshKeysBundle := rr.Response.Payload.(*identity.PublicKeyBundle)
	sshKeys := sshKeysBundle.Get()
	assetCount["ssh_key"] = len(sshKeys)

	// GPG Keys
	rr.Key.Usage = "gpg"
	rr.Key.IncludeAll = true
	err = backend.Request(operator.GetPublicKeys, rr)
	if err != nil {
		resp["message"] = "failed to extract user gpg keys"
		p.logger.Debug(
			"failed to extract user api keys",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	gpgKeysBundle := rr.Response.Payload.(*identity.PublicKeyBundle)
	gpgKeys := gpgKeysBundle.Get()
	assetCount["gpg_key"] = len(gpgKeys)

	// MFA and 2FA
	rr.MfaToken.IncludeAll = true
	if err := backend.Request(operator.GetMfaTokens, rr); err != nil {
		resp["message"] = "failed to extract user MFA/2FA"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	mfaTokensBundle := rr.Response.Payload.(*identity.MfaTokenBundle)
	mfaTokens := mfaTokensBundle.Get()
	assetCount["mfa_2fa"] = len(mfaTokens)

	// User Roles

	entry["roles"] = parsedUser.Claims.Roles

	// Finalize

	entry["asset_count"] = assetCount
	entry["connected_accounts"] = []interface{}{}
	resp["entry"] = entry
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
