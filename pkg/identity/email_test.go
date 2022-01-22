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
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestNewEmailAddress(t *testing.T) {
	testcases := []struct {
		name      string
		input     string
		primary   bool
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:  "test valid email address",
			input: "jsmith@gmail.com",
			want: map[string]interface{}{
				"address": "jsmith@gmail.com",
				"domain":  "gmail.com",
				"primary": false,
			},
		},
		{
			name:    "test valid primary email address",
			input:   "jsmith@gmail.com",
			primary: true,
			want: map[string]interface{}{
				"address": "jsmith@gmail.com",
				"domain":  "gmail.com",
				"primary": true,
			},
		},
		{
			name:      "test input with domain only",
			input:     "gmail.com",
			shouldErr: true,
			err:       errors.ErrEmailAddressInvalid,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			entry, err := NewEmailAddress(tc.input)
			if tests.EvalErrWithLog(t, err, "new email address", tc.shouldErr, tc.err, msgs) {
				return
			}
			if tc.primary {
				entry.isPrimary = true
			}
			got := make(map[string]interface{})
			got["address"] = entry.Address
			got["domain"] = entry.Domain
			got["primary"] = entry.Primary()
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
		})
	}
}
