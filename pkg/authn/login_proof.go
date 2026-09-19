// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"slices"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func passedCheckpointCount(u *user.User) int {
	n := 0
	for _, c := range u.Checkpoints {
		if c.Passed {
			n++
		}
	}
	return n
}

// recordLoginEvidence runs only under a sandbox lease, after actual checkpoint
// verification. Never advance the original authentication time after MFA.
func (p *Portal) recordLoginEvidence(u *user.User, rr *requests.Request, before int) error {
	if u.LoginEvidence.UserID == "" && (p.refreshRealm(u.Authenticator.Realm) || p.oidcRealm(u.Authenticator.Realm)) {
		return tokenrefresh.ErrDenied
	}
	if evidence := rr.Authentication; evidence.UserID != "" {
		if evidence.UserID != u.LoginEvidence.UserID || evidence.CredentialVersion != u.LoginEvidence.CredentialVersion || evidence.BackendVersion != u.LoginEvidence.BackendVersion {
			return tokenrefresh.ErrDenied
		}
	}
	if passedCheckpointCount(u) <= before {
		return nil
	}
	var methods []string
	for _, c := range u.Checkpoints {
		if !c.Passed {
			continue
		}
		// Enrollment and a client-supplied response are not verified methods.
		if !slices.Contains([]string{"pwd", "otp", "hwk"}, c.Method) {
			return tokenrefresh.ErrDenied
		}
		if !slices.Contains(methods, c.Method) {
			methods = append(methods, c.Method)
		}
		if c.Type == "mfa" {
			switch c.Method {
			case "otp":
				c.Type = "totp"
			case "hwk":
				c.Type = "u2f"
			}
		}
	}
	if u.LoginEvidence.AuthenticatedAt == 0 {
		u.LoginEvidence.AuthenticatedAt = time.Now().Unix()
		if rr.Authentication.AuthenticatedAt != 0 {
			u.LoginEvidence.AuthenticatedAt = rr.Authentication.AuthenticatedAt
		}
	}
	u.LoginMethods = methods
	return nil
}
