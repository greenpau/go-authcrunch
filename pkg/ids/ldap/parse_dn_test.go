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

package ldap

import (
	"fmt"

	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestParseFirstDN(t *testing.T) {
	testcases := []struct {
		name      string
		input     string
		want      string
		shouldErr bool
		err       error
	}{
		{
			name:      "test empty dn",
			input:     "",
			shouldErr: true,
			err:       fmt.Errorf("invalid or empty DN structure"),
		},
		{
			name:  "test ou mathematicians",
			input: "ou=mathematicians,dc=example,dc=com",
			want:  "mathematicians",
		},
		{
			name:      "test incomplete type value pair",
			input:     "foo",
			shouldErr: true,
			err:       fmt.Errorf("DN ended with incomplete type, value pair"),
		},
		{
			name:      "test iempty primary RDN",
			input:     "ou=,dc=example",
			shouldErr: true,
			err:       fmt.Errorf("empty primary RDN"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%s", tc.input))
			got, err := parseFirstDN(tc.input)
			if tests.EvalErrWithLog(t, err, "parseFirstDN", tc.shouldErr, tc.err, msgs) {
				return
			}
			tests.EvalObjectsWithLog(t, "parseFirstDN", tc.want, got, msgs)
		})
	}
}
