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

func TestMatch(t *testing.T) {

	testInput1 := "https://authcrunch.com/?redirect_uri=https://authcrunch.com/path/to/login"

	testcases := []struct {
		name      string
		config    []string
		input     string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:   "test matched exact domain and exact path match",
			config: []string{"exact", "authcrunch.com", "exact", "/path/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test exact domain and partial path match",
			config: []string{"exact", "authcrunch.com", "partial", "/to/"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test exact domain and prefix path match",
			config: []string{"exact", "authcrunch.com", "prefix", "/path/to"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test exact domain and suffix path match",
			config: []string{"exact", "authcrunch.com", "suffix", "/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test exact domain and regex path match",
			config: []string{"exact", "authcrunch.com", "regex", "/path.*login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test unmatched path",
			config: []string{"exact", "authcrunch.com", "exact", "foo"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  false,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},

		{
			name:   "test partial domain and exact path match",
			config: []string{"partial", "authcrunch.com", "exact", "/path/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test prefix domain and exact path match",
			config: []string{"prefix", "auth", "exact", "/path/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test suffix domain and exact path match",
			config: []string{"suffix", "crunch.com", "exact", "/path/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test regex domain and exact path match",
			config: []string{"regex", "auth.*com", "exact", "/path/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  true,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
		{
			name:   "test unmatched domain",
			config: []string{"exact", "authcrunch.rocks", "exact", "/path/to/login"},
			input:  testInput1,
			want: map[string]interface{}{
				"match":  false,
				"domain": "authcrunch.com",
				"path":   "/path/to/login",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%s", tc.input))

			c, err := NewRedirectURIMatchConfig(tc.config[0], tc.config[1], tc.config[2], tc.config[3])
			if err != nil {
				t.Fatal(err)
			}

			redirURI, err := ParseRedirectURI(tc.input)
			if err != nil {
				t.Fatalf("redirect uri not found in the input: %v", err)
			}

			got["match"] = Match(redirURI, []*RedirectURIMatchConfig{c})
			got["domain"] = redirURI.Host
			got["path"] = redirURI.Path

			// got, err := Parse(tc.input)
			if tests.EvalErrWithLog(t, err, "Match", tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "Output", tc.want, got, msgs)
		})
	}
}
