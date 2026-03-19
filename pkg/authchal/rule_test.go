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

package authchal

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestParseRule(t *testing.T) {
	testcases := []struct {
		name       string
		input      string
		shouldErr  bool
		err        error
		challenges []string
		conditions []string
	}{
		{
			name:       "single challenge",
			input:      "u2f",
			challenges: []string{"u2f"},
		},
		{
			name:       "multiple challenges",
			input:      "password totp",
			challenges: []string{"password", "totp"},
		},
		{
			name:       "or challenges",
			input:      "u2f or totp",
			challenges: []string{"u2f", "totp"},
		},
		{
			name:       "challenge with single condition",
			input:      "password totp if u2f not available",
			challenges: []string{"password", "totp"},
			conditions: []string{"u2f"},
		},
		{
			name:       "challenge with multiple conditions",
			input:      "password if u2f and totp not available",
			challenges: []string{"password"},
			conditions: []string{"u2f", "totp"},
		},
		{
			name:       "challenge with or and condition",
			input:      "u2f or totp if password not available",
			challenges: []string{"u2f", "totp"},
			conditions: []string{"password"},
		},
		{
			name:       "mfa challenge type",
			input:      "mfa",
			challenges: []string{"mfa"},
		},
		{
			name:      "empty input",
			input:     "",
			shouldErr: true,
			err:       fmt.Errorf("auth challenge rule: EOF"),
		},
		{
			name:      "unsupported challenge type",
			input:     "sms",
			shouldErr: true,
			err:       fmt.Errorf("unsupported challenge type: sms"),
		},
		{
			name:      "unsupported condition type",
			input:     "password if sms not available",
			shouldErr: true,
			err:       fmt.Errorf("unsupported condition type: sms"),
		},
		{
			name:      "empty condition after if",
			input:     "password if not available",
			shouldErr: true,
			err:       fmt.Errorf("empty condition in auth challenge rule"),
		},
		{
			name:      "duplicate challenge type",
			input:     "password password",
			shouldErr: true,
			err:       fmt.Errorf("duplicate challenge type: password"),
		},
		{
			name:      "condition conflicts with challenge",
			input:     "u2f if u2f not available",
			shouldErr: true,
			err:       fmt.Errorf("condition type u2f conflicts with challenge type"),
		},
		{
			name:      "starts with if keyword",
			input:     "if u2f not available",
			shouldErr: true,
			err:       fmt.Errorf("no challenge types specified"),
		},
		{
			name:      "malformed input",
			input:     `"unclosed`,
			shouldErr: true,
			err:       fmt.Errorf("auth challenge rule: parse error on line 1, column 10: extraneous or missing \" in quoted-field"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input: %s", tc.input))
			r, err := parseRule(tc.input)
			if tests.EvalErrWithLog(t, err, "parseRule", tc.shouldErr, tc.err, msgs) {
				return
			}
			tests.EvalObjectsWithLog(t, "challenges", tc.challenges, r.Challenges, msgs)
			tests.EvalObjectsWithLog(t, "conditions", tc.conditions, r.Conditions, msgs)
		})
	}
}
