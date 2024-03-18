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

package tests

import (
	"fmt"

	"testing"
)

func TestUnpackDict(t *testing.T) {

	testcases := []struct {
		name      string
		input     interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
		disabled  bool
	}{
		{
			name:     "test unpack json string",
			disabled: false,
			input: `{
				"foo": {
					"bar": "baz"
				}
			}`,
			want: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": "baz",
				},
			},
		},
		{
			name:     "test malformed json string",
			disabled: false,
			input: `{
				{
			}`,
			shouldErr: true,
			err:       fmt.Errorf("invalid character '{' looking for beginning of object key string"),
		},
		{
			name:     "test unpack map",
			disabled: false,
			input: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": "baz",
				},
			},
			want: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": "baz",
				},
			},
		},
		{
			name:      "test unpack non map",
			disabled:  false,
			input:     123,
			shouldErr: true,
			err:       fmt.Errorf("json: cannot unmarshal number into Go value of type map[string]interface {}"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%v", tc.input))
			got, err := UnpackDict(tc.input)
			if EvalErrWithLog(t, err, "UnpackDict", tc.shouldErr, tc.err, msgs) {
				return
			}
			EvalObjectsWithLog(t, "UnpackDict", tc.want, got, msgs)
		})
	}
}
