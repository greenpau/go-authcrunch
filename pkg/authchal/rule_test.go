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
	"testing"
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
			name:       "challenge with or and condition",
			input:      "u2f or totp if password not available",
			challenges: []string{"u2f", "totp"},
			conditions: []string{"password"},
		},
		{
			name:      "starts with if keyword",
			input:     "if u2f not available",
			shouldErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parseRule(tc.input)
			if tc.shouldErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strSliceEqual(r.challenges, tc.challenges) {
				t.Errorf("challenges: got %v, want %v", r.challenges, tc.challenges)
			}
			if !strSliceEqual(r.conditions, tc.conditions) {
				t.Errorf("conditions: got %v, want %v", r.conditions, tc.conditions)
			}
		})
	}
}

func strSliceEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseRuleDecodeError(t *testing.T) {
	_, err := parseRule(`"unclosed`)
	if err == nil {
		t.Fatal("expected error for malformed input")
	}
}
