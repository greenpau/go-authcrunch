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
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// OverwriteUserAuthChallenges overwrites authentication challenge rules for user identity.
func (p *Portal) OverwriteUserAuthChallenges(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	var challenges []string
	if v, exists := bodyData["challenges"]; exists {
		switch exp := v.(type) {
		case []interface{}:
			for _, ch := range exp {
				if s, ok := ch.(string); ok {
					challenges = append(challenges, s)
				}
			}
		default:
			resp["message"] = "Profile API did find key challenges in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key challenges in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if len(challenges) < 1 {
		resp["message"] = "Profile API found empty challenges in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	rr.User.Challenges = challenges
	if err := backend.Request(operator.OverwriteAuthChallengeRules, rr); err != nil {
		resp["message"] = "Profile API failed to overwrite user authentication challenge rules"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}

	resp["entries"] = rr.Response.Payload
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
