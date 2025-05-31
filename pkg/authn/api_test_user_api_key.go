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
)

// TestUserAPIKey tests API key.
func (p *Portal) TestUserAPIKey(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	rr.Key.Usage = "api"

	var keyContent string

	// Extract data.
	if v, exists := bodyData["id"]; exists {
		switch keyID := v.(type) {
		case string:
			rr.Key.ID = keyID
		default:
			resp["message"] = "Profile API did find key id in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key id in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	if v, exists := bodyData["content"]; exists {
		switch exp := v.(type) {
		case string:
			keyContent = exp
		default:
			resp["message"] = "Profile API did find key content in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key content in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if err := backend.Request(operator.GetAPIKey, rr); err != nil {
		resp["message"] = "Profile API failed to get API key"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	apiKey := rr.Response.Payload.(*identity.APIKey)

	if !apiKey.Match(keyContent) {
		resp["message"] = "Profile API failed to validate provided API key"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}

	resp["entry"] = "OK"
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
