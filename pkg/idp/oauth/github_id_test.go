// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package oauth

import (
	"strings"
	"testing"
)

func TestGithubIDFromProfile(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		wantErr          bool
	}{
		{"missing", `{"login":"alice"}`, "", false},
		{"wrong case", `{"ID":123}`, "", false},
		{"integer", `{"id":12345678}`, "12345678", false},
		{"beyond float precision", `{"id":9007199254740993}`, "9007199254740993", false},
		{"maximum", `{"id":18446744073709551615}`, "18446744073709551615", false},
		{"whitespace", "{\"id\": 42 }", "42", false},
		{"zero", `{"id":0}`, "", true},
		{"negative", `{"id":-1}`, "", true},
		{"fraction", `{"id":1.5}`, "", true},
		{"decimal", `{"id":1.0}`, "", true},
		{"exponent", `{"id":1e3}`, "", true},
		{"overflow", `{"id":18446744073709551616}`, "", true},
		{"string", `{"id":"123"}`, "", true},
		{"private string", `{"id":"private-marker"}`, "", true},
		{"null", `{"id":null}`, "", true},
		{"boolean", `{"id":true}`, "", true},
		{"object", `{"id":{"private-marker":123}}`, "", true},
		{"array", `{"id":[123]}`, "", true},
		{"invalid JSON", `{"id":01}`, "", true},
		{"trailing document", `{"id":1} {"id":2}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := githubIDFromProfile([]byte(tc.body))
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("githubIDFromProfile() = %q, %v; want %q, error %t", got, err, tc.want, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "private-marker") {
				t.Fatal("error disclosed profile content")
			}
		})
	}
}
