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
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// TestAmrClaimRoundTrip pins the amr claim across sign and parse. Stage 10
// fixed a bug where direct usr.Claims.Amr assignment did not reach the signing
// map; this test exercises sign-then-parse to assert the claim survives a
// full round trip through the keystore.
func TestAmrClaimRoundTrip(t *testing.T) {
	testcases := []struct {
		name        string
		checkpoints []*user.Checkpoint
		explicit    []string
		want        []string
	}{
		{
			name:     "password only via SetAmrClaim explicit",
			explicit: []string{"password"},
			want:     []string{"pwd"},
		},
		{
			name: "password and totp via derive from checkpoints",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				{Type: "totp", Passed: true},
			},
			want: []string{"pwd", "otp"},
		},
		{
			name: "password and u2f via derive from checkpoints",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				{Type: "u2f", Passed: true},
			},
			want: []string{"pwd", "hwk"},
		},
		{
			name: "failed checkpoint excluded",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				{Type: "totp", Passed: false},
			},
			want: []string{"pwd"},
		},
		{
			name:        "empty input produces no amr claim",
			explicit:    nil,
			checkpoints: nil,
			want:        nil,
		},
	}
	ks, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatalf("NewTestCryptoKeyStore: %v", err)
	}
	tokenName := "authp_access_token"
	for _, k := range ks.GetKeys() {
		if k.Sign.Token.Capable {
			k.Sign.Token.CookieNames[tokenName] = true
			k.Sign.Token.HeaderNames[tokenName] = true
			k.Sign.Token.QueryParamNames[tokenName] = true
		}
		if k.Verify.Token.Capable {
			k.Verify.Token.CookieNames[tokenName] = true
			k.Verify.Token.HeaderNames[tokenName] = true
			k.Verify.Token.QueryParamNames[tokenName] = true
		}
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			now := time.Now()
			usr, err := user.NewUser(map[string]interface{}{
				"sub":   "user@example.com",
				"email": "user@example.com",
				"name":  "User Example",
				"iat":   now.Unix(),
				"exp":   now.Add(10 * time.Minute).Unix(),
				"nbf":   now.Add(-1 * time.Minute).Unix(),
			})
			if err != nil {
				t.Fatalf("NewUser: %v", err)
			}

			var amr []string
			if tc.explicit != nil {
				amr = user.ToAuthMethodReferences(tc.explicit)
			} else if tc.checkpoints != nil {
				amr = deriveAmrFromCheckpoints(tc.checkpoints)
			}
			usr.SetAmrClaim(amr)

			signKey := ks.GetSignKeys()[0]
			if err := ks.SignToken(signKey.Sign.Token.Name, signKey.Sign.Token.DefaultMethod, usr); err != nil {
				t.Fatalf("SignToken: %v", err)
			}

			ar := requests.NewAuthorizationRequest()
			ar.ID = "TEST_REQUEST_ID"
			ar.SessionID = "TEST_SESSION_ID"
			ar.Token.Name = tokenName
			ar.Token.Payload = usr.Token
			ar.Token.Source = "header"
			tokenUser, err := ks.ParseToken(ar)
			if err != nil {
				t.Fatalf("ParseToken: %v", err)
			}
			tests.EvalObjectsWithLog(t, "amr", tc.want, tokenUser.Claims.Amr, msgs)
		})
	}
}
