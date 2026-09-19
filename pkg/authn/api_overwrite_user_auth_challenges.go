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

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// OverwriteUserAuthChallenges atomically replaces a bound local user's rules.
// An empty list restores defaults. Success revokes the current login evidence
// and returns reauthentication_required; the client must perform a fresh login.
func (p *Portal) OverwriteUserAuthChallenges(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	rr *requests.Request,
	_ *user.User,
	resp map[string]any,
	usr *user.User,
	backend ids.IdentityStore,
	bodyData map[string]any) error {

	challenges, err := parseProfileAuthChallenges(bodyData)
	if err != nil {
		resp["message"] = err.Error()
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	current, err := profileAuthChallengeUser(backend, rr)
	if err != nil {
		return profileAuthChallengeBackendError(w, rr, resp, err)
	}
	// Only the detached candidate changes during validation. A successful bound
	// write below must still authenticate the same immutable credential version.
	candidate := *current
	if err := candidate.OverwriteAuthChallengeRules(challenges); err != nil {
		resp["message"] = "Profile API received an invalid authentication policy"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	policy, err := p.profileAuthChallengePolicy(ctx, r, rr, usr, &candidate)
	if err != nil {
		resp["message"] = "Profile API cannot select a supported flow with the current credentials and portal policy"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	rr.User.Challenges = challenges
	if err := backend.Request(operator.OverwriteAuthChallengeRules, rr); err != nil {
		return profileAuthChallengeBackendError(w, rr, resp, err)
	}

	maps.Copy(resp, policy)
	resp["reauthentication_required"] = true
	return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
}
