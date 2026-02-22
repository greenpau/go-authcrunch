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

func TestNewPassword(t *testing.T) {
	testcases := []struct {
		name      string
		quick     bool
		purpose   string
		algorithm string
		params    map[string]interface{}
		input     string
		password  string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:     "test password",
			quick:    true,
			input:    "foobar",
			password: "foobar",
			want: map[string]interface{}{
				"purpose":        "generic",
				"algorithm":      "bcrypt",
				"cost":           10,
				"password_match": true,
			},
		},
		{
			name:      "test password with options",
			purpose:   "generic",
			algorithm: "bcrypt",
			params: map[string]interface{}{
				"cost": 10,
			},
			input:    "foobar",
			password: "foobar2",
			want: map[string]interface{}{
				"purpose":        "generic",
				"algorithm":      "bcrypt",
				"cost":           10,
				"password_match": false,
			},
		},
		{
			name:      "test password with invalid bcrypt params",
			purpose:   "generic",
			algorithm: "bcrypt",
			params: map[string]interface{}{
				"cost": 10000,
			},
			input:     "foobar",
			password:  "foobar",
			shouldErr: true,
			err:       errors.ErrPasswordGenerate.WithArgs("crypto/bcrypt: cost 10000 is outside allowed inclusive range 4..31"),
		},
		{
			name:      "test password with empty hash algorithm",
			input:     "foobar",
			shouldErr: true,
			err:       errors.ErrPasswordEmptyAlgorithm,
		},
		{
			name:      "test password with empty hash algorithm",
			algorithm: "foobar",
			input:     "foobar",
			shouldErr: true,
			err:       errors.ErrPasswordUnsupportedAlgorithm.WithArgs("foobar"),
		},
		{
			name:      "test empty password",
			input:     " ",
			shouldErr: true,
			err:       errors.ErrPasswordEmpty,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var entry *Password
			var err error
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			if tc.quick {
				entry, err = NewPassword(tc.input)
			} else {
				entry, err = NewPasswordWithOptions(tc.input, tc.purpose, tc.algorithm, tc.params)
			}
			if tests.EvalErrWithLog(t, err, "new password", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["purpose"] = entry.Purpose
			got["algorithm"] = entry.Algorithm
			got["cost"] = entry.Cost
			got["password_match"] = entry.Match(tc.password)
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
			entry.Disable()
		})
	}
}
