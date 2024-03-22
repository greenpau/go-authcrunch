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
	"fmt"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

// FetchUserUniSecFactorVerParams fetches U2F authenticator verification parameters.
func (p *Portal) FetchUserUniSecFactorVerParams(
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

	params := make(map[string]interface{})
	allowedCredential := make(map[string]interface{})

	token, err := identity.NewMfaToken(rr)
	if err != nil {
		resp["message"] = fmt.Errorf("the Profile API received malformed U2F token in the request payload: %v", err)
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if token.Parameters == nil {
		resp["message"] = "Profile API received malformed U2F token with empty parameters in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	for _, k := range []string{"id", "transports", "type"} {
		if _, exists := token.Parameters["u2f_"+k]; !exists {
			resp["message"] = fmt.Errorf("the Profile API received malformed U2F token with empty %s parameter in the request payload", k)
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
	}

	randomStr := util.GetRandomStringFromRange(64, 92)
	params["challenge"] = strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(randomStr)), "=")
	params["rp_name"] = "AuthCrunch"
	// params["rp_id"] = "auth.authcrunch.com"
	params["timeout"] = 60000
	params["user_verification"] = "discouraged"
	params["ext_uvm"] = false
	params["ext_loc"] = false
	params["ext_tx_auth_simple"] = "Could you please verify your authentication token?"
	allowedCredential["id"] = token.Parameters["u2f_id"]
	allowedCredential["type"] = token.Parameters["u2f_type"]
	allowedCredential["transports"] = strings.Split(token.Parameters["u2f_transports"], ",")
	var allowedCredentials []map[string]interface{}
	allowedCredentials = append(allowedCredentials, allowedCredential)
	params["credentials"] = allowedCredentials
	resp["entry"] = params
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
