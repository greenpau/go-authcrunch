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

package parser_test

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authchal/parser"
)

func TestParseRule(t *testing.T) {
	testcases := []struct {
		name       string
		input      string
		shouldErr  bool
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
		},
		{
			name:      "unsupported challenge type",
			input:     "sms",
			shouldErr: true,
		},
		{
			name:      "unsupported condition type",
			input:     "password if sms not available",
			shouldErr: true,
		},
		{
			name:      "empty condition after if",
			input:     "password if not available",
			shouldErr: true,
		},
		{
			name:      "duplicate challenge type",
			input:     "password password",
			shouldErr: true,
		},
		{
			name:      "condition conflicts with challenge",
			input:     "u2f if u2f not available",
			shouldErr: true,
		},
		{
			name:      "starts with if keyword",
			input:     "if u2f not available",
			shouldErr: true,
		},
		{
			name:      "malformed input",
			input:     `"unclosed`,
			shouldErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input: %s", tc.input))
			c, err := parser.NewAuthenticationChallengeConfigFromDirectives([]string{tc.input})
			if tc.shouldErr {
				if err == nil || c != nil {
					t.Fatal("invalid directive accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r := c.Rules[0]
			tests.EvalObjectsWithLog(t, "challenges", tc.challenges, r.Challenges, msgs)
			tests.EvalObjectsWithLog(t, "conditions", tc.conditions, r.Conditions, msgs)
		})
	}
}
