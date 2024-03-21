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

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

// TestUserAppMultiFactorVerifier tests app multi factor authenticator passcode.
func (p *Portal) TestUserAppMultiFactorVerifier(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {
	var tokenLifetime, tokenDigits int
	var tokenSecret, tokenPasscode string

	// Extract data.
	if v, exists := bodyData["period"]; exists {
		switch exp := v.(type) {
		case float64:
			tokenLifetime = int(exp)
		case int:
			tokenLifetime = exp
		case int64:
			tokenLifetime = int(exp)
		case json.Number:
			i, _ := exp.Int64()
			tokenLifetime = int(i)
		}
	} else {
		resp["message"] = "Profile API did not find period in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["digits"]; exists {
		switch exp := v.(type) {
		case float64:
			tokenDigits = int(exp)
		case int:
			tokenDigits = exp
		case int64:
			tokenDigits = int(exp)
		case json.Number:
			i, _ := exp.Int64()
			tokenDigits = int(i)
		}
	} else {
		resp["message"] = "Profile API did not find digits in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["secret"]; exists {
		tokenSecret = v.(string)
	} else {
		resp["message"] = "Profile API did not find secret in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["passcode"]; exists {
		tokenPasscode = v.(string)
	} else {
		resp["message"] = "Profile API did not find passcode in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Validate data.
	if !tokenSecretRegexPattern.MatchString(tokenSecret) {
		resp["message"] = "Profile API found non-compliant token secret value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if !tokenPasscodeRegexPattern.MatchString(tokenPasscode) {
		resp["message"] = "Profile API found non-compliant token passcode value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if tokenLifetime != 15 && tokenLifetime != 30 && tokenLifetime != 60 && tokenLifetime != 90 {
		resp["message"] = "Profile API found non-compliant token lifetime value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if tokenDigits != 4 && tokenDigits != 6 && tokenDigits != 8 {
		resp["message"] = "Profile API found non-compliant token digits value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	respData := make(map[string]interface{})
	appToken := identity.MfaToken{
		ID:         util.GetRandomString(40),
		CreatedAt:  time.Now().UTC(),
		Parameters: make(map[string]string),
		Flags:      make(map[string]bool),
		Comment:    "TBD",
		Type:       "totp",
		Secret:     tokenSecret,
		Algorithm:  "sha1",
		Period:     tokenLifetime,
		Digits:     tokenDigits,
	}
	if err := appToken.ValidateCodeWithTime(tokenPasscode, time.Now().Add(-time.Second*time.Duration(appToken.Period)).UTC()); err != nil {
		respData["success"] = false
	} else {
		respData["success"] = true
	}
	resp["entry"] = respData
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
