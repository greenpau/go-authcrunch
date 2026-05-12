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

package user

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestToAuthMethodReferences(t *testing.T) {
	testcases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "nil input",
			in:   nil,
			want: nil,
		},
		{
			name: "empty input",
			in:   []string{},
			want: nil,
		},
		{
			name: "password only",
			in:   []string{"password"},
			want: []string{"pwd"},
		},
		{
			name: "totp only",
			in:   []string{"totp"},
			want: []string{"otp"},
		},
		{
			name: "u2f only",
			in:   []string{"u2f"},
			want: []string{"hwk"},
		},
		{
			name: "mfa only",
			in:   []string{"mfa"},
			want: []string{"mfa"},
		},
		{
			name: "email only",
			in:   []string{"email"},
			want: []string{"mail"},
		},
		{
			name: "password and totp preserves order",
			in:   []string{"password", "totp"},
			want: []string{"pwd", "otp"},
		},
		{
			name: "totp and password preserves order",
			in:   []string{"totp", "password"},
			want: []string{"otp", "pwd"},
		},
		{
			name: "unknown keyword skipped",
			in:   []string{"password", "webauthn", "totp"},
			want: []string{"pwd", "otp"},
		},
		{
			name: "duplicates removed",
			in:   []string{"password", "password", "totp"},
			want: []string{"pwd", "otp"},
		},
		{
			name: "all unknowns yield nil",
			in:   []string{"webauthn", "biometric"},
			want: nil,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			got := ToAuthMethodReferences(tc.in)
			tests.EvalObjectsWithLog(t, "amr", tc.want, got, msgs)
		})
	}
}

// TestSetAmrClaimPropagatesToMap pins the fix for the bug where direct
// usr.Claims.Amr assignment did not reach the signing map, so SignToken
// produced JWTs without the amr claim. SetAmrClaim must update both.
func TestSetAmrClaimPropagatesToMap(t *testing.T) {
	t.Run("set propagates to AsMap", func(t *testing.T) {
		u, err := NewUser(map[string]interface{}{"sub": "user@example.com"})
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}
		u.SetAmrClaim([]string{"pwd"})
		got, exists := u.AsMap()["amr"]
		if !exists {
			t.Fatalf("amr missing from AsMap after SetAmrClaim")
		}
		tests.EvalObjectsWithLog(t, "amr in mkv", []string{"pwd"}, got, []string{"propagation"})
		tests.EvalObjectsWithLog(t, "amr in Claims", []string{"pwd"}, u.Claims.Amr, []string{"struct"})
	})
	t.Run("empty input removes from AsMap", func(t *testing.T) {
		u, _ := NewUser(map[string]interface{}{"sub": "user@example.com"})
		u.SetAmrClaim([]string{"pwd"})
		u.SetAmrClaim(nil)
		if _, exists := u.AsMap()["amr"]; exists {
			t.Fatalf("amr should be removed from AsMap when set to nil")
		}
	})
}

// TestNewUserAmr covers amr unpacking when present in the input map,
// for both []string (Go-internal callers) and []interface{} (JSON unmarshal).
func TestNewUserAmr(t *testing.T) {
	testcases := []struct {
		name    string
		input   interface{}
		want    []string
		wantErr bool
	}{
		{
			name:  "string slice",
			input: []string{"pwd", "otp"},
			want:  []string{"pwd", "otp"},
		},
		{
			name:  "interface slice (json unmarshal shape)",
			input: []interface{}{"pwd", "hwk"},
			want:  []string{"pwd", "hwk"},
		},
		{
			name:    "non-string element rejected",
			input:   []interface{}{"pwd", 42},
			wantErr: true,
		},
		{
			name:    "invalid type rejected",
			input:   "pwd",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			u, err := NewUser(map[string]interface{}{
				"sub": "user@example.com",
				"amr": tc.input,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tests.EvalObjectsWithLog(t, "amr in Claims", tc.want, u.Claims.Amr, msgs)
			tests.EvalObjectsWithLog(t, "amr in mkv", tc.want, u.AsMap()["amr"], msgs)
		})
	}
}
