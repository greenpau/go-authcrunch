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

package data

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"testing"
)

func TestGetValueFromMapByPath(t *testing.T) {
	var testcases = []struct {
		name string
		path string
		data string
		want interface{}
	}{
		{
			name: "extract nested list",
			path: "userinfo|custom_groups",
			data: testSample1,
			want: []interface{}{
				"authp/admin",
				"authp/user",
			},
		},
		{
			name: "extract nested string",
			path: "userinfo|name",
			data: testSample1,
			want: "John Smith",
		},
		{
			name: "extract sub",
			path: "sub",
			data: testSample1,
			want: "jsmith",
		},
		{
			name: "test invalid path",
			path: "userinfo|foo|bar",
			data: testSample1,
			want: "",
		},
		{
			name: "test invalid path",
			path: "foo|bar|baz",
			data: testSample1,
			want: "",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			data := make(map[string]interface{})
			json.Unmarshal([]byte(tc.data), &data)
			got := GetValueFromMapByPath(tc.path, data)
			tests.EvalObjectsWithLog(t, "GetValueFromMapByPath", tc.want, got, msgs)
		})
	}
}

var testSample1 = `{
  "userinfo": {
    "custom_groups": [
      "authp/admin",
      "authp/user"
    ],
    "name": "John Smith",
    "zoneinfo": "America/Los_Angeles",
	"foo": ["bar"]
  },
  "sub": "jsmith"
}
`
