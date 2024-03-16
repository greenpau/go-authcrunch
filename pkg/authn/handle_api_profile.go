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
	"fmt"
	"net/http"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"

	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

func handleAPIProfileResponse(w http.ResponseWriter, rr *requests.Request, code int, resp map[string]interface{}) error {
	resp["status"] = code
	rr.Response.Code = code
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}

func (p *Portal) handleAPIProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	entry := make(map[string]interface{})
	resp := make(map[string]interface{})
	resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

	if parsedUser == nil {
		resp["message"] = "Profile API received nil user"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	usr, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.logger.Warn(
			"jti session not found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("jti", parsedUser.Claims.ID),
			zap.Any("error", err),
			zap.String("source_address", addrutil.GetSourceAddress(r)),
		)
		resp["message"] = "Profile API failed to locate JTI session"
		return handleAPIProfileResponse(w, rr, http.StatusUnauthorized, resp)
	}

	if permitted := usr.HasRole("authp/admin", "authp/user"); !permitted {
		resp["message"] = "Profile API did not find valid role for the user"
		return handleAPIProfileResponse(w, rr, http.StatusForbidden, resp)
	}

	reqKind := "fetch_user_dashboard_data"

	switch usr.Authenticator.Method {
	case "local":
	default:
		resp["message"] = fmt.Sprintf("%s is not supported with profile API", usr.Authenticator.Method)
		return handleAPIProfileResponse(w, rr, 501, resp)
	}

	backend := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	if backend == nil {
		p.logger.Warn(
			"backend not found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("realm", usr.Authenticator.Realm),
			zap.String("jti", usr.Claims.ID),
			zap.String("source_address", addrutil.GetSourceAddress(r)),
		)
		resp["message"] = fmt.Sprintf("backend for %s realm not found", usr.Authenticator.Realm)
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	p.logger.Debug(
		"backend found for handling api request",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("realm", usr.Authenticator.Realm),
		zap.String("jti", usr.Claims.ID),
		zap.String("request_kind", reqKind),
		zap.String("source_address", addrutil.GetSourceAddress(r)),
	)

	// Populate username (sub) and email address (email)
	rr.User.Username = usr.Claims.Subject
	rr.User.Email = usr.Claims.Email

	switch reqKind {
	case "fetch_user_dashboard_data":
		assetCount := make(map[string]interface{})
		generalSettingsResp := make(map[string]interface{})
		if err := p.handleHTTPGeneralSettings(ctx, r, rr, usr, backend, generalSettingsResp); err != nil {
			resp["message"] = "failed to extract user metadata"
			p.logger.Debug(
				"failed to extract user metadata",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}
		if metadata, exists := generalSettingsResp["metadata"]; exists {
			entry["metadata"] = metadata
		} else {
			resp["message"] = "Profile API failed to extract user metadata"
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		// API Keys

		apiKeysResp := make(map[string]interface{})
		apiKeysResp["endpoint"] = "/list"
		if err := p.handleHTTPAPIKeysSettings(ctx, r, rr, usr, backend, apiKeysResp); err != nil {
			resp["message"] = "failed to extract user api keys"
			p.logger.Debug(
				"failed to extract user api keys",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if apikeys, exists := apiKeysResp["apikeys"]; exists {
			assetCount["api_key"] = len(apikeys.([]*identity.APIKey))
		} else {
			assetCount["api_key"] = 0
		}

		// SSH Keys

		sshKeysResp := make(map[string]interface{})
		sshKeysResp["endpoint"] = "/list"
		if err := p.handleHTTPSSHKeysSettings(ctx, r, rr, usr, backend, sshKeysResp); err != nil {
			resp["message"] = "failed to extract user ssh keys"
			p.logger.Debug(
				"failed to extract user ssh keys",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if sshkeys, exists := sshKeysResp["sshkeys"]; exists {
			assetCount["ssh_key"] = len(sshkeys.([]*identity.PublicKey))
		} else {
			assetCount["ssh_key"] = 0
		}

		// GPG Keys

		gpgKeysResp := make(map[string]interface{})
		gpgKeysResp["endpoint"] = "/list"
		if err := p.handleHTTPGPGKeysSettings(ctx, r, rr, usr, backend, gpgKeysResp); err != nil {
			resp["message"] = "failed to extract user gpg keys"
			p.logger.Debug(
				"failed to extract user gpg keys",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if gpgkeys, exists := gpgKeysResp["gpgkeys"]; exists {
			assetCount["gpg_key"] = len(gpgkeys.([]*identity.PublicKey))
		} else {
			assetCount["gpg_key"] = 0
		}

		// MFA/2FA

		mfa2faResp := make(map[string]interface{})
		mfa2faResp["endpoint"] = "/list"
		if err := p.handleHTTPMfaSettings(ctx, r, rr, usr, backend, mfa2faResp); err != nil {
			resp["message"] = "failed to extract user MFA/2FA"
			p.logger.Debug(
				"failed to extract user MFA/2FA",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if mfaTokens, exists := mfa2faResp["mfa_tokens"]; exists {
			assetCount["mfa_2fa"] = len(mfaTokens.([]*identity.MfaToken))
		} else {
			assetCount["mfa_2fa"] = 0
		}

		// User Roles

		entry["roles"] = parsedUser.Claims.Roles

		// Finalize

		entry["asset_count"] = assetCount
		entry["connected_accounts"] = []interface{}{}
		resp["entry"] = entry
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
	default:
		resp["message"] = fmt.Sprintf("unsupported %s request kind with profile API", reqKind)
		return handleAPIProfileResponse(w, rr, 501, resp)
	}
}
