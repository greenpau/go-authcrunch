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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

// TestTransformUserAmrEndToEnd asserts the amr claim survives the full
// transformUser-to-JWT path. Covers regression (no transformer rule), a
// `require auth challenges` match, and a `require auth challenges` miss.
func TestTransformUserAmrEndToEnd(t *testing.T) {
	testcases := []struct {
		name               string
		transformerConfigs []*transformer.Config
		userAuthMethods    []string
		checkpoints        []*user.Checkpoint
		wantChallenges     []string
		wantAmr            []string
		wantErrSubstring   string
	}{
		{
			name:            "regression: nil transformer is a no-op",
			userAuthMethods: []string{"password"},
		},
		{
			name: "require auth challenges password matches user methods",
			transformerConfigs: []*transformer.Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  []string{"require auth challenges password"},
				},
			},
			userAuthMethods: []string{"password"},
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
			},
			wantChallenges: []string{"password"},
			wantAmr:        []string{"pwd"},
		},
		{
			name: "require auth challenges u2f fails when user has only password",
			transformerConfigs: []*transformer.Config{
				{
					Matchers: []string{"exact match email user@example.com"},
					Actions:  []string{"require auth challenges u2f"},
				},
			},
			userAuthMethods:  []string{"password"},
			wantErrSubstring: "no rule matched",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			p := &Portal{logger: zap.L()}
			if len(tc.transformerConfigs) > 0 {
				tf, err := transformer.NewFactory(tc.transformerConfigs)
				if err != nil {
					t.Fatalf("NewFactory: %v", err)
				}
				p.transformer = tf
			}

			rr := requests.NewRequest()
			rr.User.AuthMethods = tc.userAuthMethods
			m := map[string]interface{}{
				"email": "user@example.com",
				"sub":   "user@example.com",
			}

			err := p.transformUser(context.Background(), rr, m)
			if tc.wantErrSubstring != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstring) {
					t.Fatalf("transformUser: want err containing %q, got %v", tc.wantErrSubstring, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("transformUser: %v", err)
			}
			if tc.transformerConfigs == nil {
				for _, key := range []string{"auth_methods", "challenges", "realm"} {
					if _, exists := m[key]; exists {
						t.Fatalf("nil transformer touched m[%q]", key)
					}
				}
				return
			}
			if _, exists := m["auth_methods"]; exists {
				t.Fatalf("auth_methods key leaked into m after transformUser")
			}
			if tc.wantChallenges != nil {
				got, _ := m["challenges"].([]string)
				tests.EvalObjectsWithLog(t, "challenges", tc.wantChallenges, got, msgs)
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
			usr.SetAmrClaim(deriveAmrFromCheckpoints(tc.checkpoints))

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
			tests.EvalObjectsWithLog(t, "amr", tc.wantAmr, tokenUser.Claims.Amr, msgs)
		})
	}
}
