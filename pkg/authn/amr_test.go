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
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestDeriveAmrFromCheckpoints(t *testing.T) {
	testcases := []struct {
		name        string
		checkpoints []*user.Checkpoint
		want        []string
	}{
		{
			name:        "nil checkpoints",
			checkpoints: nil,
			want:        nil,
		},
		{
			name:        "empty checkpoints",
			checkpoints: []*user.Checkpoint{},
			want:        nil,
		},
		{
			name: "single passed password",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
			},
			want: []string{"pwd"},
		},
		{
			name: "password and totp both passed",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				{Type: "totp", Passed: true},
			},
			want: []string{"pwd", "otp"},
		},
		{
			name: "mixed passed and unpassed",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				{Type: "totp", Passed: false},
				{Type: "u2f", Passed: true},
			},
			want: []string{"pwd", "hwk"},
		},
		{
			name: "no passed checkpoints",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: false},
				{Type: "totp", Passed: false},
			},
			want: nil,
		},
		{
			name: "nil checkpoint entry skipped",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				nil,
				{Type: "totp", Passed: true},
			},
			want: []string{"pwd", "otp"},
		},
		{
			name: "unknown checkpoint type skipped",
			checkpoints: []*user.Checkpoint{
				{Type: "password", Passed: true},
				{Type: "webauthn", Passed: true},
				{Type: "totp", Passed: true},
			},
			want: []string{"pwd", "otp"},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			got := deriveAmrFromCheckpoints(tc.checkpoints)
			tests.EvalObjectsWithLog(t, "amr", tc.want, got, msgs)
		})
	}
}
