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
	"fmt"
	"slices"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authchal"
)

func TestGetRegisteredAuthMethodsPasswordAvailability(t *testing.T) {
	for _, tc := range []struct {
		name      string
		passwords []*Password
		want      []string
	}{
		{name: "passwordless"},
		{name: "nil entry", passwords: []*Password{nil}},
		{name: "disabled", passwords: []*Password{{Hash: dummyPasswordHash, Disabled: true}}},
		{name: "expired", passwords: []*Password{{Hash: dummyPasswordHash, Expired: true}}},
		{name: "active", passwords: []*Password{nil, {Hash: dummyPasswordHash, Disabled: true}, {Hash: dummyPasswordHash}}, want: []string{authchal.PasswordKeyword}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{Passwords: tc.passwords}
			if got := user.GetRegisteredAuthMethods(); !slices.Equal(got, tc.want) {
				t.Fatalf("registered methods %v; want %v", got, tc.want)
			}
			for _, external := range []bool{false, true} {
				user.ExternallyProvisioned = external
				want := []string{authchal.PasswordKeyword}
				if external && len(tc.passwords) == 0 {
					want = nil
				}
				got, err := user.GetChallenges()
				if err != nil || !slices.Equal(got, want) {
					t.Fatalf("default challenges %v, error %v; want %v (external=%t)", got, err, want, external)
				}
			}
		})
	}
}

func TestGetChallengesDisabledToken(t *testing.T) {
	user := &User{
		Passwords: []*Password{{Hash: dummyPasswordHash}},
		MfaTokens: []*MfaToken{
			{Type: "totp", Disabled: true},
			{Type: "u2f"},
		},
	}
	msgs := []string{"disabled totp token should be skipped"}
	got, err := user.GetChallenges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{authchal.PasswordKeyword, authchal.U2fKeyword}
	tests.EvalObjectsWithLog(t, "challenges", want, got, msgs)
}

func TestDefaultChallengesKeepUnavailablePassword(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password *Password
	}{
		{"disabled", &Password{Hash: dummyPasswordHash, Disabled: true}},
		{"expired", &Password{Hash: dummyPasswordHash, Expired: true}},
	} {
		for _, external := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/external=%t", tc.name, external), func(t *testing.T) {
				u := &User{ExternallyProvisioned: external, Passwords: []*Password{tc.password}, MfaTokens: []*MfaToken{{Type: "totp"}}}
				if slices.Contains(u.GetRegisteredAuthMethods(), authchal.PasswordKeyword) {
					t.Fatal("unavailable password counted as usable")
				}
				got, err := u.GetChallenges()
				if err != nil || !slices.Equal(got, []string{"password", "totp"}) {
					t.Fatalf("password removal weakened default challenges: %v, error %v", got, err)
				}
				if err := u.OverwriteAuthChallengeRules([]string{"totp"}); err != nil {
					t.Fatal(err)
				}
				got, err = u.GetChallenges()
				if err != nil || !slices.Equal(got, []string{"totp"}) {
					t.Fatalf("explicit passwordless policy lost: %v, error %v", got, err)
				}
			})
		}
	}
}

func TestGetChallengesAllDisabled(t *testing.T) {
	user := &User{
		Passwords: []*Password{{Hash: dummyPasswordHash}},
		MfaTokens: []*MfaToken{
			{Type: "totp", Disabled: true},
			{Type: "u2f", Disabled: true},
		},
	}
	msgs := []string{"all tokens disabled, password only"}
	got, err := user.GetChallenges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{authchal.PasswordKeyword}
	tests.EvalObjectsWithLog(t, "challenges", want, got, msgs)
}

func TestGetChallengesWithRules(t *testing.T) {
	user := &User{
		Passwords: []*Password{{Hash: dummyPasswordHash}},
		MfaTokens: []*MfaToken{
			{Type: "u2f"},
		},
	}
	if err := user.AddAuthChallengeRule("u2f"); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}
	if err := user.AddAuthChallengeRule("password if u2f not available"); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}
	msgs := []string{"u2f rule should match"}
	got, err := user.GetChallenges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{authchal.U2fKeyword}
	tests.EvalObjectsWithLog(t, "challenges", want, got, msgs)
}

func TestGetChallengesCorruptRuleReturnsError(t *testing.T) {
	user := &User{
		AuthChallengeRules: []string{"valid_rule_this_is_not"},
	}
	msgs := []string{"corrupt rule should return error"}
	_, err := user.GetChallenges()
	if err == nil {
		t.Fatalf("expected error for corrupt rule")
	}
	tests.EvalErrWithLog(t, err, "GetChallenges", true, fmt.Errorf("authentication challenge directive at line 1: unsupported challenge type"), msgs)
}

func TestOverwriteAuthChallengeRules(t *testing.T) {
	user := &User{
		Passwords: []*Password{{Hash: dummyPasswordHash}},
		MfaTokens: []*MfaToken{{Type: "u2f"}},
	}
	if err := user.OverwriteAuthChallengeRules([]string{"u2f", "password if u2f not available"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msgs := []string{"overwrite should set rules"}
	tests.EvalObjectsWithLog(t, "rules", []string{"u2f", "password if u2f not available"}, user.GetAuthChallengeRules(), msgs)

	got, err := user.GetChallenges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tests.EvalObjectsWithLog(t, "challenges", []string{authchal.U2fKeyword}, got, msgs)

	// second call uses cached ruleset
	got, err = user.GetChallenges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tests.EvalObjectsWithLog(t, "challenges cached", []string{authchal.U2fKeyword}, got, msgs)
}

func TestOverwriteAuthChallengeRulesInvalid(t *testing.T) {
	user := &User{}
	msgs := []string{"invalid rule should return error"}
	err := user.OverwriteAuthChallengeRules([]string{"sms"})
	tests.EvalErrWithLog(t, err, "OverwriteAuthChallengeRules", true, fmt.Errorf("authentication challenge directive at line 1: unsupported challenge type"), msgs)
}

func TestAddAuthChallengeRuleInvalid(t *testing.T) {
	user := &User{}
	msgs := []string{"invalid rule should return error"}
	err := user.AddAuthChallengeRule("sms")
	tests.EvalErrWithLog(t, err, "AddAuthChallengeRule", true, fmt.Errorf("authentication challenge directive at line 1: unsupported challenge type"), msgs)
}

func TestGetChallengesEmail(t *testing.T) {
	testcases := []struct {
		name   string
		tokens []*MfaToken
		rules  []string
		want   []string
	}{
		{
			name:   "email token only",
			tokens: []*MfaToken{{Type: "email"}},
			want:   []string{authchal.PasswordKeyword, authchal.EmailKeyword},
		},
		{
			name:   "email and totp",
			tokens: []*MfaToken{{Type: "email"}, {Type: "totp"}},
			want:   []string{authchal.PasswordKeyword, authchal.MfaKeyword},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			user := &User{Passwords: []*Password{{Hash: dummyPasswordHash}}, MfaTokens: tc.tokens}
			for _, rule := range tc.rules {
				if err := user.AddAuthChallengeRule(rule); err != nil {
					t.Fatalf("failed to add rule: %v", err)
				}
			}
			got, err := user.GetChallenges()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tests.EvalObjectsWithLog(t, "challenges", tc.want, got, msgs)
		})
	}
}
