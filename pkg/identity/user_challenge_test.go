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
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authchal"
)

func TestGetChallengesDisabledToken(t *testing.T) {
	user := &User{
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

func TestGetChallengesAllDisabled(t *testing.T) {
	user := &User{
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
	tests.EvalErrWithLog(t, err, "GetChallenges", true, fmt.Errorf("unsupported challenge type: valid_rule_this_is_not"), msgs)
}
