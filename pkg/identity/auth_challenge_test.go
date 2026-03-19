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

package identity

import (
	"testing"
)

func TestParseAuthChallengeRule(t *testing.T) {
	testcases := []struct {
		name       string
		input      string
		shouldErr  bool
		challenges []string
		conditions []string
	}{
		{
			name:       "single challenge without conditions",
			input:      "u2f",
			challenges: []string{"u2f"},
		},
		{
			name:       "multiple challenges without conditions",
			input:      "password totp",
			challenges: []string{"password", "totp"},
		},
		{
			name:       "challenges with single condition",
			input:      "password totp if u2f not available",
			challenges: []string{"password", "totp"},
			conditions: []string{"u2f"},
		},
		{
			name:       "challenges with multiple conditions",
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
			name:      "condition conflicts with challenge type",
			input:     "u2f if u2f not available",
			shouldErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := ParseAuthChallengeRule(tc.input)
			if tc.shouldErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strSliceEqual(rule.Challenges, tc.challenges) {
				t.Errorf("challenges: got %v, want %v", rule.Challenges, tc.challenges)
			}
			if !strSliceEqual(rule.Conditions, tc.conditions) {
				t.Errorf("conditions: got %v, want %v", rule.Conditions, tc.conditions)
			}
		})
	}
}

func TestGetChallengesWithRules(t *testing.T) {
	testcases := []struct {
		name       string
		tokenTypes []string
		rules      []string
		want       []string
	}{
		{
			name:       "u2f available and preferred",
			tokenTypes: []string{"u2f"},
			rules: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			want: []string{"u2f"},
		},
		{
			name:       "totp only, u2f not available",
			tokenTypes: []string{"totp"},
			rules: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			want: []string{"password", "totp"},
		},
		{
			name:       "no mfa tokens, password fallback",
			tokenTypes: nil,
			rules: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			want: []string{"password"},
		},
		{
			name:       "both totp and u2f available, first rule wins",
			tokenTypes: []string{"totp", "u2f"},
			rules: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			want: []string{"u2f"},
		},
		{
			name:       "no rules, default behavior with no mfa",
			tokenTypes: nil,
			rules:      nil,
			want:       []string{"password"},
		},
		{
			name:       "no rules, default behavior with totp",
			tokenTypes: []string{"totp"},
			rules:      nil,
			want:       []string{"password", "totp"},
		},
		{
			name:       "no rules, default behavior with u2f",
			tokenTypes: []string{"u2f"},
			rules:      nil,
			want:       []string{"password", "u2f"},
		},
		{
			name:       "no rules, default behavior with both",
			tokenTypes: []string{"totp", "u2f"},
			rules:      nil,
			want:       []string{"password", "mfa"},
		},
		{
			name:       "rules with no matching fallback returns default",
			tokenTypes: nil,
			rules: []string{
				"u2f",
			},
			want: []string{"password"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{}
			for _, tt := range tc.tokenTypes {
				user.MfaTokens = append(user.MfaTokens, &MfaToken{Type: tt})
			}
			for _, rs := range tc.rules {
				if err := user.AddAuthChallengeRule(rs); err != nil {
					t.Fatalf("failed to add rule %q: %v", rs, err)
				}
			}

			got := user.GetChallenges()
			if !strSliceEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetChallengesEmptyRulesIgnored(t *testing.T) {
	// Rules with empty Challenges (bypassing the parser) must
	// not produce an empty challenge list.
	user := &User{
		AuthChallengeRules: []*AuthChallengeRule{
			{Challenges: []string{}},
			{Challenges: nil},
			nil,
		},
	}
	got := user.GetChallenges()
	if len(got) == 0 {
		t.Fatal("GetChallenges returned empty list, auth bypass possible")
	}
	if got[0] != "password" {
		t.Errorf("got %v, want [password]", got)
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
