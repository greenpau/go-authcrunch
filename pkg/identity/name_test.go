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

	"github.com/greenpau/aaasf/internal/tests"
	"github.com/greenpau/aaasf/pkg/errors"
)

func TestNewName(t *testing.T) {
	testcases := []struct {
		name      string
		fullName  string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:     "test name",
			fullName: "John Smith",
			want: map[string]interface{}{
				"claim":     "Smith, John",
				"full_name": "Smith, John",
			},
		},
		{
			name:      "test parse name error",
			fullName:  "foobar",
			shouldErr: true,
			err:       errors.ErrParseNameFailed.WithArgs("foobar"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			NewName()
			entry, err := ParseName(tc.fullName)
			if tests.EvalErrWithLog(t, err, "parse name", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["claim"] = entry.GetNameClaim()
			got["full_name"] = entry.GetFullName()
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
		})
	}
}
