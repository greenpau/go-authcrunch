// Copyright 2024 Paul Greenberg greenpau@outlook.com
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

package redirects

import (
	"fmt"

	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestParseRedirectURI(t *testing.T) {

	testcases := []struct {
		name      string
		input     string
		want      map[string]interface{}
		shouldErr bool
		err       error
		disabled  bool
	}{
		{
			name:     "test valid redirect uri",
			disabled: false,
			input:    "https://authcrunch.com/?redirect_uri=https://authcrunch.com/path/to/login",
			want: map[string]interface{}{
				"redirect_uri": "https://authcrunch.com/path/to/login",
			},
		},
		{
			name:      "test parse invalid base uri",
			disabled:  false,
			input:     "http://authcrunch.com.%24/?redirect_uri=https://authcrunch.com/path/to/login",
			shouldErr: true,
			err:       fmt.Errorf("failed to parse base uri"),
		},
		{
			name:      "test parse non compliant base uri",
			disabled:  false,
			input:     "http:authcrunch.com/?redirect_uri=https://authcrunch.com/path/to/login",
			shouldErr: true,
			err:       fmt.Errorf("non compliant base uri"),
		},
		// {
		// 	name:      "test parse invalid redirect uri",
		// 	disabled:  false,
		// 	input:     "http://authcrunch.com/?redirect_uri=https://authcrunch.com.%24/path/to/login",
		// 	shouldErr: true,
		// 	err:       fmt.Errorf("failed to parse redirect uri"),
		// },
		{
			name:      "test parse redirect uri without host",
			disabled:  false,
			input:     "https://authcrunch.com/?redirect_uri=/foo/bar",
			shouldErr: true,
			err:       fmt.Errorf("redirect uri has no scheme and host"),
		},
		{
			name:      "test parse non compliant redirect uri",
			disabled:  false,
			input:     "http://authcrunch.com/?redirect_uri=authcrunch.com/path/to/login",
			shouldErr: true,
			err:       fmt.Errorf("non compliant redirect uri"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			var err error
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%s", tc.input))

			redirURI, err := ParseRedirectURI(tc.input)
			if tests.EvalErrWithLog(t, err, "RedirectURI", tc.shouldErr, tc.err, msgs) {
				return
			}

			got["redirect_uri"] = redirURI.String()

			tests.EvalObjectsWithLog(t, "RedirectURI", tc.want, got, msgs)
		})
	}
}
