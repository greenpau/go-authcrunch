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
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestNewDomainRuleset(t *testing.T) {
	testcases := []struct {
		name       string
		statements []string
		want       any
		shouldErr  bool
		err        error
	}{
		{
			name:       "multiple allow domains with exact",
			statements: []string{"allow domain foo.com", "allow domain bar.com"},
			want: map[string]any{
				"default_action": float64(1),
				"rules": []any{
					map[string]any{
						"action_type":       "allow",
						"domain":            "foo.com",
						"domain_match_type": "exact",
					},
					map[string]any{
						"action_type":       "allow",
						"domain":            "bar.com",
						"domain_match_type": "exact",
					},
				},
			},
		},
		{
			name:       "allow suffix followed by deny regex",
			statements: []string{"allow suffix domain .microsoft.com", "deny regex domain ^(gmail|outlook)."},
			want: map[string]any{
				"default_action": float64(2),
				"rules": []any{
					map[string]any{
						"action_type":       "allow",
						"domain":            ".microsoft.com",
						"domain_match_type": "suffix",
					},
					map[string]any{
						"action_type":       "deny",
						"domain":            "^(gmail|outlook).",
						"domain_match_type": "regex",
					},
				},
			},
		},
		{
			name:       "multiple deny domains with exact",
			statements: []string{"deny domain anonymous-mail.com", "deny domain temporary-inbox.org"},
			want: map[string]any{
				"default_action": float64(2),
				"rules": []any{
					map[string]any{
						"action_type":       "deny",
						"domain":            "anonymous-mail.com",
						"domain_match_type": "exact",
					},
					map[string]any{
						"action_type":       "deny",
						"domain":            "temporary-inbox.org",
						"domain_match_type": "exact",
					},
				},
			},
		},
		{
			name:       "malformed ruleset",
			statements: []string{"deny foo.bar"},
			shouldErr:  true,
			err:        errors.ErrUserRegistryConfigMalformedDomainRestrictionRule.WithArgs("deny foo.bar"),
		},
		{
			name:       "ruleset without rule statement",
			statements: []string{},
			shouldErr:  true,
			err:        fmt.Errorf("no rule statements found"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.statements))
			rs, err := NewDomainRestrictionRuleset(tc.statements)
			if tests.EvalErrWithLog(t, err, "NewDomainRestrictionRuleset", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := tests.Unpack(t, map[string]any{"rules": rs.rules, "default_action": rs.defaultAction})
			tests.EvalObjectsWithLog(t, "NewDomainRestrictionRuleset", tc.want, got, msgs)
		})
	}
}
