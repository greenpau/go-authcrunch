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

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

// TestUserUniSecFactorReg verifies U2F authenticator.
func (p *Portal) TestUserUniSecFactorReg(
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

	// Validate inputs.
	if v, exists := bodyData["webauthn_register"]; exists {
		rr.WebAuthn.Register = v.(string)
	} else {
		resp["message"] = "Profile API did not find webauthn_register in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["webauthn_challenge"]; exists {
		rr.WebAuthn.Challenge = v.(string)
	} else {
		resp["message"] = "Profile API did not find webauthn_challenge in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["webauthn_request"]; exists {
		rr.WebAuthn.Request = v.(string)
	} else {
		resp["message"] = "Profile API did not find webauthn_request in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	token, err := identity.NewMfaToken(rr)
	if err != nil {
		resp["message"] = "Profile API received malformed U2F token in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

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
	// TODO: replace with true
	respData["success"] = true
	resp["entry"] = respData
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
