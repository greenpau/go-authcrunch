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

package apiauth

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestParseAuthRequest(t *testing.T) {
	testcases := []struct {
		name                 string
		input                string
		hasChallengeResponse bool
		want                 *AuthRequest
		shouldErr            bool
		err                  error
	}{
		{
			name:  "test valid initial auth request",
			input: `{"username": "jsmith", "realm": "local"}`,
			want: &AuthRequest{
				Username: "jsmith",
				Realm:    "local",
			},
		},
		{
			name:  "test valid challenge response auth request",
			input: `{"username": "jsmith", "realm": "local", "sandbox_id": "foo", "sandbox_secret": "baz", "challenge_kind": "password", "challenge_response": "bar"}`,
			want: &AuthRequest{
				Username:          "jsmith",
				Realm:             "local",
				SandboxID:         "foo",
				SandboxSecret:     "baz",
				ChallengeKind:     "password",
				ChallengeResponse: "bar",
			},
			hasChallengeResponse: true,
		},
		{
			name:      "test invalid json",
			input:     `{"username": "jsmith",`,
			shouldErr: true,
			err:       fmt.Errorf("unexpected EOF"),
		},
		{
			name:      "test unknown field",
			input:     `{"username": "jsmith", "realm": "local", "foo": "bar"}`,
			shouldErr: true,
			err:       fmt.Errorf("json: unknown field \"foo\""),
		},
		{
			name:      "test validation failure during parse",
			input:     `{"realm": "local"}`,
			shouldErr: true,
			err:       fmt.Errorf("required username field is empty"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%s", tc.input))

			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/auth", strings.NewReader(tc.input))
			ctx := context.Background()

			got, err := ParseAuthRequest(ctx, w, r)
			if tests.EvalErrWithLog(t, err, "ParseAuthRequest", tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "Username", tc.want.Username, got.Username, msgs)
			tests.EvalObjectsWithLog(t, "Realm", tc.want.Realm, got.Realm, msgs)
			tests.EvalObjectsWithLog(t, "Realm", tc.want.Realm, got.Realm, msgs)
			tests.EvalObjectsWithLog(t, "SandboxID", tc.want.SandboxID, got.SandboxID, msgs)
			tests.EvalObjectsWithLog(t, "SandboxSecret", tc.want.SandboxSecret, got.SandboxSecret, msgs)
			tests.EvalObjectsWithLog(t, "ChallengeKind", tc.want.ChallengeKind, got.ChallengeKind, msgs)
			tests.EvalObjectsWithLog(t, "ChallengeResponse", tc.want.ChallengeResponse, got.ChallengeResponse, msgs)
			tests.EvalObjectsWithLog(t, "HasChallengeResponse", tc.hasChallengeResponse, got.HasChallengeResponse(), msgs)

		})
	}
}

func TestValidateAuthRequest(t *testing.T) {
	testcases := []struct {
		name      string
		input     *AuthRequest
		want      map[string]string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid initial auth request",
			input: &AuthRequest{
				Username: "jsmith",
				Realm:    "default",
			},
			want: map[string]string{
				"realm":    "default",
				"username": "jsmith",
			},
		},
		{
			name: "test valid challenge response auth request",
			input: &AuthRequest{
				Username:          "jsmith",
				Realm:             "default",
				SandboxID:         "foo",
				SandboxSecret:     "baz",
				ChallengeKind:     "password",
				ChallengeResponse: "bar",
			},
			want: map[string]string{
				"realm":              "default",
				"username":           "jsmith",
				"sandbox_id":         "foo",
				"sandbox_secret":     "baz",
				"challenge_kind":     "password",
				"challenge_response": "bar",
			},
		},
		{
			name: "test empty username",
			input: &AuthRequest{
				Username: " ",
				Realm:    "default",
			},
			shouldErr: true,
			err:       fmt.Errorf("required username field is empty"),
		},
		{
			name: "test empty realm",
			input: &AuthRequest{
				Username: "jsmith",
				Realm:    "",
			},
			shouldErr: true,
			err:       fmt.Errorf("required realm field is empty"),
		},
		{
			name: "test missing sandbox_id for challenge",
			input: &AuthRequest{
				Username:          "jsmith",
				Realm:             "default",
				ChallengeResponse: "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf("required sandbox_id field is empty"),
		},
		{
			name: "test missing sandbox_secret for challenge",
			input: &AuthRequest{
				Username:      "jsmith",
				Realm:         "default",
				SandboxID:     "foo",
				ChallengeKind: "password",
			},
			shouldErr: true,
			err:       fmt.Errorf("required sandbox_secret field is empty"),
		},
		{
			name: "test missing challenge_kind for challenge",
			input: &AuthRequest{
				Username:      "jsmith",
				Realm:         "default",
				SandboxID:     "foo",
				SandboxSecret: "bar",
			},
			shouldErr: true,
			err:       fmt.Errorf("required challenge_kind field is empty"),
		},
		{
			name: "test missing challenge_response for challenge",
			input: &AuthRequest{
				Username:      "jsmith",
				Realm:         "default",
				SandboxID:     "foo",
				SandboxSecret: "bar",
				ChallengeKind: "password",
			},
			shouldErr: true,
			err:       fmt.Errorf("required challenge_response field is empty"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			err := tc.input.Validate()
			if tests.EvalErrWithLog(t, err, "Validate", tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "ChallengeKind", tc.want, tc.input.AsStringMap(), msgs)
		})
	}
}
