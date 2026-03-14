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

package registry

import (
	"fmt"

	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestDomainRulesetShouldDeny(t *testing.T) {
	testcases := []struct {
		name       string
		statements []string
		input      string
		shouldDeny bool
	}{
		{
			name:       "should allow based on explicit allow and exact match with default deny",
			statements: []string{"allow domain foo.com", "allow domain bar.com"},
			input:      "foo.com",
			shouldDeny: false,
		},
		{
			name:       "should allow based on exact match with default allow",
			statements: []string{"deny domain foo.com", "deny domain bar.com"},
			input:      "baz.com",
			shouldDeny: false,
		},
		{
			name:       "should allow based on explicit allow and exact match with default deny",
			statements: []string{"allow suffix domain .microsoft.com", "deny regex domain ^(gmail|outlook)."},
			input:      "foo.com",
			shouldDeny: false,
		},
		{
			name:       "should deny based on default deny and exact match",
			statements: []string{"allow domain foo.com", "allow domain bar.com"},
			input:      "baz.com",
			shouldDeny: true,
		},
		{
			name:       "should allow based on explicit allow and partial match with default deny",
			statements: []string{"allow partial domain microsoft"},
			input:      "microsoft.com",
			shouldDeny: false,
		},
		{
			name:       "should allow based on explicit allow and prefix match with default deny",
			statements: []string{"allow prefix domain microsoft"},
			input:      "microsoft.com",
			shouldDeny: false,
		},
		{
			name:       "should allow based on explicit allow and suffix match with default deny",
			statements: []string{"allow suffix domain .com"},
			input:      "microsoft.com",
			shouldDeny: false,
		},
		{
			name:       "should allow based on explicit allow and regex match with default deny",
			statements: []string{cfgutil.EncodeArgs([]string{"allow", "regex", "domain", "\\.edu"})},
			input:      "nyu.edu",
			shouldDeny: false,
		},
		{
			name:       "should deny based on regex match with default allow",
			statements: []string{cfgutil.EncodeArgs([]string{"deny", "regex", "domain", "\\.edu"})},
			input:      "nyu.edu",
			shouldDeny: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("statements:\n%v", tc.statements))
			rs, err := NewDomainRestrictionRuleset(tc.statements)
			if tests.EvalErrWithLog(t, err, "NewDomainRestrictionRuleset", false, nil, msgs) {
				return
			}
			tests.EvalObjectsWithLog(t, "ShouldDeny", tc.shouldDeny, rs.ShouldDeny(tc.input), msgs)
		})
	}
}
