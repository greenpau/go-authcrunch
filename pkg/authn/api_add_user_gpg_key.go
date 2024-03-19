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
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

var gpgKeyTitleRegexPattern = regexp.MustCompile(`^[\w\@\.\s\(\)<>,\-+:]+$`)

// AddUserGPGKey adds GPG key to user identity.
func (p *Portal) AddUserGPGKey(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	var keyTitle, keyDescription, keyPayload string
	var keyLabels []string = []string{}
	var keyTags []tagging.Tag = []tagging.Tag{}

	// Extract data.
	if v, exists := bodyData["content"]; exists {
		switch exp := v.(type) {
		case string:
			keyPayload = strings.TrimSpace(exp)
		default:
			resp["message"] = "Profile API did find key content in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key content in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["title"]; exists {
		keyTitle = v.(string)
	} else {
		resp["message"] = "Profile API did not find title in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["description"]; exists {
		keyDescription = v.(string)
	} else {
		resp["message"] = "Profile API did not find description in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if extractedTokenTags, err := tagging.ExtractTags(bodyData); err == nil {
		for _, extractedTokenTag := range extractedTokenTags {
			keyTags = append(keyTags, *extractedTokenTag)
		}
	} else {
		resp["message"] = "Profile API find malformed tags in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if extractedTokenLabels, err := tagging.ExtractLabels(bodyData); err == nil {
		keyLabels = extractedTokenLabels
	} else {
		resp["message"] = "Profile API find malformed tags in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Validate data.
	if !gpgKeyTitleRegexPattern.MatchString(keyTitle) {
		resp["message"] = "Profile API found non-compliant GPG key title value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if !tokenDescriptionRegexPattern.MatchString(keyDescription) && (keyDescription != "") {
		resp["message"] = "Profile API found non-compliant GPG key description value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if !gpgKeyRegexPattern1.MatchString(keyPayload) && !gpgKeyRegexPattern2.MatchString(keyPayload) {
		resp["message"] = "Profile API found non-compliant GPG public key value"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	rr.Key.Usage = "gpg"
	rr.Key.Comment = keyTitle
	rr.Key.Description = keyDescription
	rr.Key.Payload = keyPayload
	rr.Key.Labels = keyLabels
	rr.Key.Tags = keyTags

	if err := backend.Request(operator.AddKeyGPG, rr); err != nil {
		var errMsg string = fmt.Sprintf("the Profile API failed to add GPG key to identity store: %v", err)
		resp["message"] = errMsg
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	resp["entry"] = "Created"
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
