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

func TestNewRuleset(t *testing.T) {
	testcases := []struct {
		name       string
		statements []string
		shouldErr  bool
		err        error
	}{
		{
			name:       "valid single rule",
			statements: []string{"u2f"},
		},
		{
			name: "valid full chain",
			statements: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
		},
		{
			name: "valid or rule",
			statements: []string{
				"u2f or totp",
				"password if u2f and totp not available",
			},
		},
		{
			name:      "empty statements",
			shouldErr: true,
			err:       fmt.Errorf("no auth challenge rule statements found"),
		},
		{
			name:       "invalid rule in chain",
			statements: []string{"u2f", "sms"},
			shouldErr:  true,
			err:        fmt.Errorf("unsupported challenge type: sms"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			_, err := NewRuleset(tc.statements)
			if tests.EvalErrWithLog(t, err, "NewRuleset", tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestRulesetDump(t *testing.T) {
	rs, err := NewRuleset([]string{"u2f", "password if u2f not available"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := rs.Dump()
	if out == "" || out == "{}" {
		t.Errorf("Dump() returned empty: %s", out)
	}

	var nilRs *Ruleset
	if nilRs.Dump() != "{}" {
		t.Errorf("nil Dump() should return {}")
	}
}

func TestRulesetResolveChallenges(t *testing.T) {
	testcases := []struct {
		name       string
		statements []string
		registered map[string]bool
		want       []string
	}{
		{
			name: "u2f available and preferred",
			statements: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{"u2f": true},
			want:       []string{"u2f"},
		},
		{
			name: "totp only, u2f not available",
			statements: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{"totp": true},
			want:       []string{"password", "totp"},
		},
		{
			name: "no mfa tokens, password fallback",
			statements: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{},
			want:       []string{"password"},
		},
		{
			name: "both available, first rule wins",
			statements: []string{
				"u2f",
				"password totp if u2f not available",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{"totp": true, "u2f": true},
			want:       []string{"u2f"},
		},
		{
			name: "or rule with one available",
			statements: []string{
				"u2f or totp",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{"u2f": true},
			want:       []string{"u2f", "totp"},
		},
		{
			name: "or rule with neither available falls through",
			statements: []string{
				"u2f or totp",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{},
			want:       []string{"password"},
		},
		{
			name: "mfa rule with totp registered",
			statements: []string{
				"mfa",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{"totp": true},
			want:       []string{"mfa"},
		},
		{
			name: "mfa rule with neither registered",
			statements: []string{
				"mfa",
				"password if u2f and totp not available",
			},
			registered: map[string]bool{},
			want:       []string{"password"},
		},
		{
			name: "no matching rule returns nil",
			statements: []string{
				"u2f",
			},
			registered: map[string]bool{},
		},
		{
			name: "conditional rule with condition met",
			statements: []string{
				"password if u2f not available",
			},
			registered: map[string]bool{},
			want:       []string{"password"},
		},
		{
			name: "conditional rule with condition not met",
			statements: []string{
				"password totp if u2f not available",
			},
			registered: map[string]bool{"u2f": true, "totp": true},
		},
		{
			name: "mfa rule with email registered",
			statements: []string{
				"mfa",
				"password if email not available",
			},
			registered: map[string]bool{"email": true},
			want:       []string{"mfa"},
		},
		{
			name: "three mfa types, first rule wins",
			statements: []string{
				"u2f",
				"email or totp",
				"password if u2f and totp and email not available",
			},
			registered: map[string]bool{"totp": true, "u2f": true, "email": true},
			want:       []string{"u2f"},
		},
		{
			name: "or rule with password skips password in availability check",
			statements: []string{
				"password or totp",
			},
			registered: map[string]bool{"totp": true},
			want:       []string{"password", "totp"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			rs, err := NewRuleset(tc.statements)
			if err != nil {
				t.Fatalf("failed to create ruleset: %v", err)
			}
			got := rs.ResolveChallenges(tc.registered)
			tests.EvalObjectsWithLog(t, "challenges", tc.want, got, msgs)
		})
	}
}

func TestRulesetResolveChallengesNilRule(t *testing.T) {
	rs := &Ruleset{
		Rules: []*Rule{
			nil,
			{Challenges: []string{"password"}},
		},
	}
	got := rs.ResolveChallenges(map[string]bool{})
	tests.EvalObjectsWithLog(t, "challenges", []string{"password"}, got, []string{"nil rule skipped"})
}
