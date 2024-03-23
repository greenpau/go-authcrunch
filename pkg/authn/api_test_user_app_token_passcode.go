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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// TestUserAppTokenPasscode tests app multi factor authenticator passcode.
func (p *Portal) TestUserAppTokenPasscode(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	var tokenPasscode string

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

	if v, exists := bodyData["passcode"]; exists {
		switch exp := v.(type) {
		case string:
			tokenPasscode = exp
		default:
			resp["message"] = "Profile API did find key passcode in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key passcode in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Validate data.
	if !tokenPasscodeRegexPattern.MatchString(tokenPasscode) {
		resp["message"] = "Profile API found non-compliant token passcode value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Get MFA Token
	if err := backend.Request(operator.GetMfaToken, rr); err != nil {
		resp["message"] = "Profile API failed to get application authenticator"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	appToken := rr.Response.Payload.(*identity.MfaToken)
	respData := make(map[string]interface{})
	if err := appToken.ValidateCodeWithTime(tokenPasscode, time.Now().Add(-time.Second*time.Duration(appToken.Period)).UTC()); err != nil {
		respData["success"] = false
	} else {
		respData["success"] = true
	}
	resp["entry"] = respData
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
