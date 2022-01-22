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

func TestNewRole(t *testing.T) {
	testcases := []struct {
		name      string
		input     string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:  "test role without org",
			input: "superadmin",
			want: map[string]interface{}{
				"name": "superadmin",
				"org":  "",
				"role": "superadmin",
			},
		},
		{
			name:  "test role with org",
			input: "internal/superadmin",
			want: map[string]interface{}{
				"name": "superadmin",
				"org":  "internal",
				"role": "internal/superadmin",
			},
		},
		{
			name:      "test empty role",
			input:     "",
			shouldErr: true,
			err:       errors.ErrRoleEmpty,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			entry, err := NewRole(tc.input)
			if tests.EvalErrWithLog(t, err, "new role", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["name"] = entry.Name
			got["org"] = entry.Organization
			got["role"] = entry.String()
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
		})
	}
}
