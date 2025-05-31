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

// TestUserWebAuthnToken tests WebAuthn token.
func (p *Portal) TestUserWebAuthnToken(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	rr.MfaToken.Type = "u2f"

	// Extract data.
	if v, exists := bodyData["id"]; exists {
		switch keyID := v.(type) {
		case string:
			rr.MfaToken.ID = keyID
		default:
			resp["message"] = "Profile API did find key id in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key id in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if v, exists := bodyData["webauthn_challenge"]; exists {
		switch exp := v.(type) {
		case string:
			rr.WebAuthn.Challenge = exp
		default:
			resp["message"] = "Profile API did find key webauthn_challenge in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key webauthn_challenge in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if v, exists := bodyData["webauthn_request"]; exists {
		switch exp := v.(type) {
		case string:
			rr.WebAuthn.Request = exp
		default:
			resp["message"] = "Profile API did find key webauthn_request in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key webauthn_request in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Get MFA Token
	if err := backend.Request(operator.GetMfaToken, rr); err != nil {
		resp["message"] = "Profile API failed to get token"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}

	token := rr.Response.Payload.(*identity.MfaToken)

	wr, err := token.WebAuthnRequest(rr.WebAuthn.Request)
	if err != nil {
		p.logger.Warn(
			"u2f token validation failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("webauthn_request", wr),
			zap.Any("error", err),
		)
		resp["message"] = "Profile API failed to validate U2F token"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	p.logger.Debug(
		"Profile API successfully validated u2f token",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.Any("webauthn_request", wr),
	)

	respData := make(map[string]interface{})
	respData["success"] = true
	resp["entry"] = respData
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
