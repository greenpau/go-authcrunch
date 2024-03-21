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

func TestNewRedirectURIMatchConfig(t *testing.T) {
	testcases := []struct {
		name      string
		config    []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:   "text exact domain and exact path match",
			config: []string{"exact", "authcrunch.com", "exact", "/path/to"},
			want: map[string]interface{}{
				"domain_match_type": "exact",
				"domain":            "authcrunch.com",
				"path_match_type":   "exact",
				"path":              "/path/to",
			},
		},
		{
			name:      "test undefined redirect uri domain",
			config:    []string{"exact", " ", "exact", "/path/to"},
			shouldErr: true,
			err:       fmt.Errorf("undefined redirect uri domain"),
		},
		{
			name:      "test undefined redirect uri domain name match type",
			config:    []string{"", "authcrunch.com", "exact", "/path/to"},
			shouldErr: true,
			err:       fmt.Errorf("undefined redirect uri domain name match type"),
		},
		{
			name:      "test unsupported redirect uri domain name match type",
			config:    []string{"foo", "authcrunch.com", "exact", "/path/to"},
			shouldErr: true,
			err:       fmt.Errorf("invalid %q redirect uri domain name match type", "foo"),
		},
		{
			name:      "test bad redirect uri domain name regex",
			config:    []string{"regex", "[.", "exact", "/path/to"},
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ]: `[.`"),
		},
		{
			name:      "test undefined redirect uri path",
			config:    []string{"exact", "authcrunch.com", "exact", " "},
			shouldErr: true,
			err:       fmt.Errorf("undefined redirect uri path"),
		},
		{
			name:      "test undefined redirect uri path match type",
			config:    []string{"exact", "authcrunch.com", "", "/path/to"},
			shouldErr: true,
			err:       fmt.Errorf("undefined redirect uri path match type"),
		},
		{
			name:      "test unsupported redirect uri path match type",
			config:    []string{"exact", "authcrunch.com", "foo", "/path/to"},
			shouldErr: true,
			err:       fmt.Errorf("invalid %q redirect uri path match type", "foo"),
		},
		{
			name:      "test bad redirect uri path regex",
			config:    []string{"regex", "authcrunch.rocks", "exact", "[."},
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ]: `[.`"),
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
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			c, err := NewRedirectURIMatchConfig(tc.config[0], tc.config[1], tc.config[2], tc.config[3])
			if tests.EvalErrWithLog(t, err, "Match", tc.shouldErr, tc.err, msgs) {
				return
			}

			got["domain_match_type"] = c.DomainMatchType
			got["domain"] = c.Domain
			got["path_match_type"] = c.PathMatchType
			got["path"] = c.Path

			tests.EvalObjectsWithLog(t, "Output", tc.want, got, msgs)
		})
	}
}
