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
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// AddUserUniSecFactorToken adds U2F token to user identity.
func (p *Portal) AddUserUniSecFactorToken(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	var tokenTitle, tokenDescription string
	var tokenLabels []string = []string{}
	var tokenTags []tagging.Tag = []tagging.Tag{}

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

	rr.MfaToken.Type = "u2f"
	rr.MfaToken.Comment = tokenTitle
	rr.MfaToken.Description = tokenDescription
	rr.MfaToken.Tags = tokenTags
	rr.MfaToken.Labels = tokenLabels

	if err := backend.Request(operator.AddMfaToken, rr); err != nil {
		resp["message"] = "Profile API failed to add token to identity store"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	resp["entry"] = "Created"
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
