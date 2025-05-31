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

// FetchUserSSHKeys fetches SSH keys from user identity.
func (p *Portal) FetchUserSSHKeys(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore) error {

	rr.Key.Usage = "ssh"
	if err := backend.Request(operator.GetPublicKeys, rr); err != nil {
		resp["message"] = "Profile API failed to get SSH keys"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	bundle := rr.Response.Payload.(*identity.PublicKeyBundle)
	sshKeys := bundle.Get()
	// for _, sshKey := range sshKeys {
	// 	sshKey.Payload = ""
	// 	sshKey.OpenSSH = ""
	// }
	resp["entries"] = sshKeys

	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}

// FetchUserSSHKey fetches SSH key from user identity.
func (p *Portal) FetchUserSSHKey(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	parsedUser *user.User,
	resp map[string]interface{},
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]interface{}) error {

	rr.Key.Usage = "ssh"
	if v, exists := bodyData["id"]; exists {
		rr.Key.ID = v.(string)
	} else {
		resp["message"] = "Profile API did not find id in the request payload"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if err := backend.Request(operator.GetPublicKey, rr); err != nil {
		resp["message"] = "Profile API failed to get SSH key"
		return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
	}
	token := rr.Response.Payload.(*identity.PublicKey)
	resp["entry"] = token
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
