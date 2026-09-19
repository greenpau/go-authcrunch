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

package identity

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestRegisteredAuthenticationMethods(t *testing.T) {
	u := &User{MfaTokens: []*MfaToken{nil, {Type: "totp"}, {Type: "u2f", Disabled: true}, {Type: "totp"}, {Type: "email"}, {Type: "unknown"}}}
	if got := fmt.Sprint(u.GetRegisteredAuthMethods()); got != "[password totp email]" {
		t.Fatal(got)
	}
	methods := u.GetRegisteredAuthMethods()
	methods[0] = "changed"
	if u.GetRegisteredAuthMethods()[0] != "password" {
		t.Fatal("inventory aliases caller")
	}
	u.AuthChallengeRules = []string{"u2f"}
	if _, err := u.GetChallenges(); err == nil {
		t.Fatal("unavailable explicit policy silently fell back")
	}
	if err := u.OverwriteAuthChallengeRules([]string{"password", "invalid"}); err == nil || fmt.Sprint(u.AuthChallengeRules) != "[u2f]" {
		t.Fatal("invalid policy mutated existing policy")
	}
}

func TestIdentifyRegisteredAuthenticationMethods(t *testing.T) {
	db, err := createTestDatabase("TestIdentifyRegisteredAuthenticationMethods")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{testUser1, "nonexistent"} {
		req := &requests.Request{User: requests.User{Username: name, AuthChallengePolicy: true}}
		if err := db.IdentifyUser(req); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(req.User.AuthMethods) != "[password]" {
			t.Fatal("identification omitted inventory")
		}
		if req.User.AuthChallengePolicy {
			t.Fatal("identification retained a stale policy marker")
		}
	}
	if err := db.OverwriteUserAuthChallengeRules(&requests.Request{User: requests.User{Username: testUser1, Email: testEmail1, Challenges: []string{"password"}}}); err != nil {
		t.Fatal(err)
	}
	explicit := &requests.Request{User: requests.User{Username: testUser1}}
	if err := db.IdentifyUser(explicit); err != nil || !explicit.User.AuthChallengePolicy {
		t.Fatal("identification lost explicit policy", err)
	}
	u, err := db.getUser(testUser1)
	if err != nil {
		t.Fatal(err)
	}
	u.Disabled = true
	req := &requests.Request{User: requests.User{Username: testUser1, AuthChallengePolicy: true}}
	if err := db.IdentifyUser(req); err != nil || fmt.Sprint(req.User.AuthMethods) != "[password]" || req.User.AuthChallengePolicy {
		t.Fatal("disabled identity inventory", err)
	}
}
