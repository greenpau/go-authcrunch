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
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

// FetchUserUniSecFactorRegParams fetches U2F authenticator registration parameters.
func (p *Portal) FetchUserUniSecFactorRegParams(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	params := make(map[string]interface{})
	randomStr := util.GetRandomStringFromRange(64, 92)
	params["challenge"] = strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(randomStr)), "=")
	params["rp_name"] = "AuthCrunch"
	// params["rp_id"] = "auth.authcrunch.com"
	params["user_id"] = usr.Claims.ID
	params["user_name"] = usr.Claims.Email
	params["user_verification"] = "discouraged"
	params["attestation"] = "direct"
	if usr.Claims.Name == "" {
		params["user_display_name"] = usr.Claims.Subject
	} else {
		params["user_display_name"] = usr.Claims.Name
	}

	resp["entry"] = params
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
