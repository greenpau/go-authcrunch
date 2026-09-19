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
	"maps"
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// FetchUserAuthChallenges returns stored rules and a preview of the effective
// login policy for the bound local identity and the current request context.
func (p *Portal) FetchUserAuthChallenges(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	_ *user.User,
	resp map[string]any,
	usr *user.User,
	backend ids.IdentityStore) error {

	current, err := profileAuthChallengeUser(backend, rr)
	if err != nil {
		return profileAuthChallengeBackendError(w, rr, resp, err)
	}
	policy, err := p.profileAuthChallengePolicy(ctx, r, rr, usr, current)
	if err != nil {
		resp["message"] = "Profile API could not resolve the current authentication policy"
		return handleAPIProfileResponse(w, rr, http.StatusConflict, resp)
	}
	maps.Copy(resp, policy)
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
