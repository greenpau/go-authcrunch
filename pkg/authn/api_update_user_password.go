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
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// UpdateUserPassword updates user password.
func (p *Portal) UpdateUserPassword(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	if v, exists := bodyData["old_password"]; exists {
		switch exp := v.(type) {
		case string:
			rr.User.OldPassword = strings.TrimSpace(exp)
		default:
			resp["message"] = "Profile API did find key old_password in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key old_password in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if v, exists := bodyData["new_password"]; exists {
		switch exp := v.(type) {
		case string:
			rr.User.Password = strings.TrimSpace(exp)
		default:
			resp["message"] = "Profile API did find key new_password in the request payload, but it is malformed"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	} else {
		resp["message"] = "Profile API did not find key new_password in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if err := backend.Request(operator.ChangePassword, rr); err != nil {
		var errMsg string = fmt.Sprintf("the Profile API failed to change user password in identity store: %v", err)
		resp["message"] = errMsg
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	resp["entry"] = "Updated"
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
