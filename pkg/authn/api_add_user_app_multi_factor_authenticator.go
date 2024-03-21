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

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// AddUserAppMultiFactorVerifier adds app multi factor authenticator to user identity.
func (p *Portal) AddUserAppMultiFactorVerifier(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	var tokenTitle, tokenDescription, tokenSecret string
	var tokenLifetime, tokenDigits int
	var tokenLabels []string = []string{}
	var tokenTags []tagging.Tag = []tagging.Tag{}

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
	if v, exists := bodyData["title"]; exists {
		tokenTitle = v.(string)
	} else {
		resp["message"] = "Profile API did not find title in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["description"]; exists {
		tokenDescription = v.(string)
	} else {
		resp["message"] = "Profile API did not find description in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["secret"]; exists {
		tokenSecret = v.(string)
	} else {
		resp["message"] = "Profile API did not find secret in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if extractedTokenTags, err := tagging.ExtractTags(bodyData); err == nil {
		for _, extractedTokenTag := range extractedTokenTags {
			tokenTags = append(tokenTags, *extractedTokenTag)
		}
	} else {
		resp["message"] = "Profile API find malformed tags in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if extractedTokenLabels, err := tagging.ExtractLabels(bodyData); err == nil {
		tokenLabels = extractedTokenLabels
	} else {
		resp["message"] = "Profile API find malformed tags in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Validate data.
	if !tokenIssuerRegexPattern.MatchString(tokenTitle) {
		resp["message"] = "Profile API found non-compliant token title value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if !tokenDescriptionRegexPattern.MatchString(tokenDescription) && (tokenDescription != "") {
		resp["message"] = "Profile API found non-compliant token description value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if !tokenSecretRegexPattern.MatchString(tokenSecret) {
		resp["message"] = "Profile API found non-compliant token secret value"
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

	rr.MfaToken.SkipVerification = true
	rr.MfaToken.Comment = tokenTitle
	rr.MfaToken.Description = tokenDescription
	rr.MfaToken.Secret = tokenSecret
	rr.MfaToken.Type = "totp"
	rr.MfaToken.Period = tokenLifetime
	rr.MfaToken.Digits = tokenDigits
	rr.MfaToken.Labels = tokenLabels
	rr.MfaToken.Tags = tokenTags

	if err := backend.Request(operator.AddMfaToken, rr); err != nil {
		resp["message"] = "Profile API failed to add token identity store"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	resp["entry"] = "Created"
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
