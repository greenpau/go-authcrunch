// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestLoginEvidenceVerifiedMethods(t *testing.T) {
	for _, tc := range []struct{ kind, method, want string }{{"password", "pwd", "password"}, {"mfa", "otp", "totp"}, {"mfa", "hwk", "u2f"}, {"mfa", "", ""}} {
		t.Run(tc.kind+"/"+tc.method, func(t *testing.T) {
			portal := &Portal{}
			u := &user.User{Checkpoints: []*user.Checkpoint{{Type: tc.kind, Passed: true, Method: tc.method}}}
			// Unverified request fields must not override the successful checkpoint.
			rr := &requests.Request{User: requests.User{Password: "unverified"}, MfaToken: requests.MfaToken{Passcode: "123456"}}
			err := portal.recordLoginEvidence(u, rr, 0)
			if tc.want == "" {
				if err == nil {
					t.Fatal("enrollment treated as authentication")
				}
				return
			}
			if err != nil || fmt.Sprint(u.LoginMethods) != "["+tc.method+"]" || u.Checkpoints[0].Type != tc.want {
				t.Fatal("incorrect method evidence", err)
			}
			at := u.LoginEvidence.AuthenticatedAt
			if err := portal.recordLoginEvidence(u, rr, 1); err != nil || len(u.LoginMethods) != 1 || at != u.LoginEvidence.AuthenticatedAt {
				t.Fatal("unchanged checkpoint altered evidence")
			}
		})
	}
}

func TestDirectAuthenticationPolicy(t *testing.T) {
	for _, tc := range []struct {
		selected            bool
		required, completed []string
		additional          []string
		deny                bool
	}{
		{true, []string{"password"}, []string{"password"}, nil, false},
		{true, []string{"password", "totp"}, []string{"password"}, nil, true},
		{true, []string{"password"}, nil, nil, true},
		{false, []string{"password"}, nil, nil, false},
		{false, []string{"password", "totp"}, nil, nil, false},
		{false, []string{"totp"}, []string{"password"}, nil, true},
		{false, []string{"u2f"}, []string{"password"}, nil, true},
		{false, []string{"password", "totp"}, []string{"password"}, nil, true},
		{false, []string{"password"}, []string{"password"}, []string{"totp"}, true},
		{false, []string{"password"}, nil, []string{"totp"}, true},
		{true, []string{"invalid"}, []string{"password"}, nil, true},
	} {
		p := &Portal{}
		rr := &requests.Request{User: requests.User{Challenges: tc.required, AuthChallengePolicy: tc.selected}}
		claims := map[string]any{}
		if tc.additional != nil {
			claims["challenges"] = tc.additional
		}
		if err := p.checkDirectAuthenticationPolicy(rr, claims, tc.completed); (err != nil) != tc.deny {
			t.Fatalf("unexpected direct authentication decision: %v", err)
		}
	}
}
