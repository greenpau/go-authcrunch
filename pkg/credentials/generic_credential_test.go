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

package credentials

import (
	// "fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"

	"testing"
)

func TestGenericCredential(t *testing.T) {
	testcases := []struct {
		name      string
		entry     []string
		want      map[string]any
		shouldErr bool
		err       error
	}{
		{
			name: "test valid generic credential with domain",
			entry: []string{
				"name default",
				"username foo",
				"password bar",
				"domain example.com",
			},
			want: map[string]any{
				"name":     "default",
				"kind":     "generic",
				"username": "foo",
				"password": "bar",
				"domain":   "example.com",
			},
		},
		{
			name: "test generic credential with unsupported kind",
			entry: []string{
				"name default",
				"kind foo",
				"username foo",
				"password bar",
				"domain example.com",
			},
			shouldErr: true,
			err:       errors.ErrCredMalformedInstructionKindMismatch.WithArgs(GenericCredentialKindLabel, "foo"),
		},
		{
			name: "test bad credential syntax with unsupported keyword",
			entry: []string{
				"foo bar",
			},
			shouldErr: true,
			err:       errors.ErrCredMalformedInstructionUnsupportedKey.WithArgs("foo bar"),
		},
		{
			name: "test bad credential syntax with too many args",
			entry: []string{
				"foo bar baz",
			},
			shouldErr: true,
			err:       errors.ErrCredMalformedInstructionBadSyntax.WithArgs("foo bar baz"),
		},
		{
			name: "bad credential instruction encoding",
			entry: []string{
				"",
			},
			shouldErr: true,
			err:       errors.ErrCredMalformedInstructionThrown.WithArgs("EOF", ""),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := NewGenericCredential(tc.entry)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}

			got := cred.AsMap()
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("NewGenericCredential() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
