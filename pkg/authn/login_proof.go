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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/refresh"
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
	if !p.refreshRealm(u.Authenticator.Realm) {
		return nil
	}
	if u.LoginEvidence.UserID == "" {
		return refresh.ErrDenied
	}
	if evidence := rr.Authentication; evidence.UserID != "" {
		if evidence.UserID != u.LoginEvidence.UserID || evidence.CredentialVersion != u.LoginEvidence.CredentialVersion || evidence.BackendVersion != u.LoginEvidence.BackendVersion {
			return refresh.ErrDenied
		}
	}
	if passedCheckpointCount(u) <= before {
		return nil
	}
	method := ""
	switch {
	case rr.User.Password != "":
		method = "pwd"
	case rr.MfaToken.Passcode != "":
		method = "otp"
	case rr.WebAuthn.Request != "":
		method = "hwk"
	}
	// Enrollment alone is not proof of possession for a renewable session.
	if method == "" {
		return refresh.ErrDenied
	}
	if u.LoginEvidence.AuthenticatedAt == 0 {
		u.LoginEvidence.AuthenticatedAt = time.Now().Unix()
		if rr.Authentication.AuthenticatedAt != 0 {
			u.LoginEvidence.AuthenticatedAt = rr.Authentication.AuthenticatedAt
		}
	}
	u.LoginMethods = append(u.LoginMethods, method)
	// Record the concrete factor when the generic MFA checkpoint was selected.
	for _, c := range u.Checkpoints {
		if c.Passed && c.Type == "mfa" {
			if method == "otp" {
				c.Type = "totp"
			}
			if method == "hwk" {
				c.Type = "u2f"
			}
		}
	}
	return nil
}
