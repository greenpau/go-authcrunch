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

package kms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"testing"
)

func TestParsePayloadFromToken(t *testing.T) {
	var testcases = []struct {
		name      string
		input     map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "valid token payload",
			input: map[string]interface{}{
				"email_verified":   true,
				"cognito:username": "jsmith",
				"custom:roles":     "authp/admin authp/user",
				"custom:timezone":  "America/New_York",
			},
			want: map[string]interface{}{
				"email_verified":   true,
				"cognito:username": "jsmith",
				"custom:roles":     "authp/admin authp/user",
				"custom:timezone":  "America/New_York",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}

			input, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatal(err)
			}

			got, err := ParsePayloadFromToken("foo." + base64.StdEncoding.EncodeToString(input) + ".bar")
			if tests.EvalErrWithLog(t, err, "TestParsePayloadFromToken", tc.shouldErr, tc.err, msgs) {
				return
			}
			tests.EvalObjects(t, "TestParsePayloadFromToken", tc.want, got)
		})
	}
}
