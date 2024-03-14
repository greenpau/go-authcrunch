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

	testInput1 := "https://authcrunch.com/?redirect_uri=https://authcrunch.com/path/to/login"

	testcases := []struct {
		name      string
		input     string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:  "text valid redirect uri",
			input: testInput1,
			want: map[string]interface{}{
				"redirect_uri": "https://authcrunch.com/path/to/login",
			},
		},
		/*
			{
				name: "test invalid config",
				shouldErr: true,
				err:       fmt.Errorf("TBD"),
			},
		*/
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%s", tc.input))

			redirURI := ParseRedirectURI(tc.input)
			if redirURI == nil {
				err = fmt.Errorf("redirect uri not found")
			}

			if tests.EvalErrWithLog(t, err, "Match", tc.shouldErr, tc.err, msgs) {
				return
			}

			got["redirect_uri"] = redirURI.String()

			tests.EvalObjectsWithLog(t, "RedirectURI", tc.want, got, msgs)
		})
	}
}
