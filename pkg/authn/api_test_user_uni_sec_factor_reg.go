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

	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
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
	if v, exists, ok := getProfileAPIStringField(bodyData, "webauthn_register"); exists {
		if !ok {
			resp["message"] = "Profile API did find webauthn_register in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		rr.WebAuthn.Register = v
	} else {
		resp["message"] = "Profile API did not find webauthn_register in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists, ok := getProfileAPIStringField(bodyData, "webauthn_challenge"); exists {
		if !ok {
			resp["message"] = "Profile API did find webauthn_challenge in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		rr.WebAuthn.Challenge = v
	} else {
		resp["message"] = "Profile API did not find webauthn_challenge in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists, ok := getProfileAPIStringField(bodyData, "webauthn_request"); exists {
		if !ok {
			resp["message"] = "Profile API did find webauthn_request in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		rr.WebAuthn.Request = v
	} else {
		resp["message"] = "Profile API did not find webauthn_request in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	binding, err := getWebAuthnEnrollmentBinding(r, rr, usr, "profile")
	if err == nil {
		err = p.webAuthnEnrollments.verify(binding, rr)
	}
	if err != nil {
		resp["message"] = errWebAuthnEnrollment.Error()
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	respData := make(map[string]interface{})
	respData["success"] = true
	resp["entry"] = respData
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
