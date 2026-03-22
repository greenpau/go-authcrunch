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
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewDomainRestrictionRule(t *testing.T) {
	testcases := []struct {
		name      string
		statement string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:      "test exact domain match",
			statement: cfgutil.EncodeArgs([]string{"allow", "domain", "authcrunch.com"}),
			want: map[string]interface{}{
				"action_type":       "allow",
				"domain_match_type": "exact",
				"domain":            "authcrunch.com",
			},
		},
		{
			name:      "test partial domain match",
			statement: cfgutil.EncodeArgs([]string{"allow", "partial", "domain", "crunch.com"}),
			want: map[string]interface{}{
				"action_type":       "allow",
				"domain_match_type": "partial",
				"domain":            "crunch.com",
			},
		},
		{
			name:      "test prefix domain match",
			statement: cfgutil.EncodeArgs([]string{"allow", "prefix", "domain", "authcrunch."}),
			want: map[string]interface{}{
				"action_type":       "allow",
				"domain_match_type": "prefix",
				"domain":            "authcrunch.",
			},
		},
		{
			name:      "test undefined domain",
			statement: cfgutil.EncodeArgs([]string{"allow", "exact", "domain", " "}),
			shouldErr: true,
			err:       fmt.Errorf("undefined domain"),
		},
		{
			name:      "test undefined domain name match type",
			statement: cfgutil.EncodeArgs([]string{"allow", "", "domain", "authcrunch.com"}),
			shouldErr: true,
			err:       fmt.Errorf("undefined domain name match type"),
		},
		{
			name:      "test unsupported domain name match type",
			statement: cfgutil.EncodeArgs([]string{"allow", "foo", "domain", "authcrunch.com"}),
			shouldErr: true,
			err:       fmt.Errorf("invalid %q domain name match type", "foo"),
		},
		{
			name:      "test bad domain name regex",
			statement: cfgutil.EncodeArgs([]string{"allow", "regex", "domain", "[."}),
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ]: `[.`"),
		},
		{
			name:      "test bad domain name regex",
			statement: cfgutil.EncodeArgs([]string{"allow", "regex", "domain", "[."}),
			shouldErr: true,
			err:       fmt.Errorf("error parsing regexp: missing closing ]: `[.`"),
		},
		{
			name:      "test bad encoding",
			statement: "allow domain \"foo.bar",
			shouldErr: true,
			err:       fmt.Errorf("failed to decode domain restriction rule: allow domain \"foo.bar"),
		},
		{
			name:      "test missing domain keyword",
			statement: "allow foo foo.bar",
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedDomainRestrictionRule.WithArgs("allow foo foo.bar"),
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
			msgs = append(msgs, fmt.Sprintf("statement:\n%s", tc.statement))
			c, err := NewDomainRestrictionRule(tc.statement)
			if tests.EvalErrWithLog(t, err, "NewDomainRestrictionConfig", tc.shouldErr, tc.err, msgs) {
				return
			}

			got["domain_match_type"] = c.DomainMatchType
			got["domain"] = c.Domain
			got["action_type"] = c.ActionType

			tests.EvalObjectsWithLog(t, "NewDomainRestrictionConfig", tc.want, got, msgs)
		})
	}
}

func TestValidateDomainRestrictionRule(t *testing.T) {
	testcases := []struct {
		name      string
		rule      *DomainRestrictionRule
		shouldErr bool
		err       error
	}{
		{
			name: "test unknown action type",
			rule: &DomainRestrictionRule{
				DomainMatchType: "exact",
				Domain:          "authcrunch.com",
				ActionType:      "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid %q action type", "foo"),
		},
		{
			name: "test undefined action type",
			rule: &DomainRestrictionRule{
				DomainMatchType: "exact",
				Domain:          "authcrunch.com",
				ActionType:      "",
			},
			shouldErr: true,
			err:       fmt.Errorf("undefined action type"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("rule:\n%v", tc.rule))
			err := tc.rule.Validate()
			if tests.EvalErrWithLog(t, err, "Validate", tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
