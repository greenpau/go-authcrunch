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

package acl

import (
	"context"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"testing"
	"time"
)

func TestNewAccessList(t *testing.T) {
	var testcases = []struct {
		name         string
		config       []*RuleConfiguration
		batch        bool
		defaultAllow bool
		input        map[string]interface{}
		want         map[string]interface{}
		shouldErr    bool
		err          error
	}{
		{
			name: "new access list with logging",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `allow any stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with batched conditions",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `allow any stop log`,
				},
			},
			batch: true,
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with default allow",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `allow any stop log`,
				},
			},
			defaultAllow: true,
			input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with invalid conditions",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"",
						"",
					},
					Action: `allow any stop log`,
				},
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, failed to extract condition tokens: EOF"),
		},
		{
			name: "new access list with invalid batched conditions",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"",
						"",
					},
					Action: `allow any stop log`,
				},
			},
			batch:     true,
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, failed to extract condition tokens: EOF"),
		},

		{
			name: "new access list with allow verdict",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `allow any log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with deny verdict",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `deny any log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": false,
			},
		},
		{
			name: "new access list with deny and stop verdict",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `deny any stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": false,
			},
		},
		{
			name: "new access list with default deny",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `deny any stop log`,
				},
			},
			input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"allow": false,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			ctx := context.Background()
			logger := logutil.NewLogger()
			accessList := NewAccessList()
			accessList.SetLogger(logger)
			if tc.defaultAllow {
				accessList.SetDefaultAllowAction()
			}
			if tc.batch {
				err = accessList.AddRules(ctx, tc.config)
				if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
					return
				}
			} else {
				for _, rule := range tc.config {
					err = accessList.AddRule(ctx, rule)
					if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
						return
					}
				}
			}

			tc.want["rule_count"] = len(tc.config)
			got := make(map[string]interface{})
			got["allow"] = accessList.Allow(ctx, tc.input)
			got["rule_count"] = len(accessList.GetRules())

			tests.EvalObjects(t, "eval", tc.want, got)
		})
	}
}

func TestCustomAccessList(t *testing.T) {
	var testcases = []struct {
		name         string
		config       []*RuleConfiguration
		disabled     bool
		defaultAllow bool
		input        map[string]interface{}
		// want         map[string]interface{}
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "deny roles foobar",
			config: []*RuleConfiguration{
				{
					Comment: "match roles foobar and deny",
					Conditions: []string{
						"match roles foobar",
					},
					Action: `deny stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: `{
              "allow": false,
              "config": {
                "count": 1,
                "rules": [
                  {
                    "action": "ruleActionDeny",
                    "comment": "match roles foobar and deny",
                    "conditions": [
                      {
                        "always_true": false,
                        "condition_type": "ruleStrCondExactMatchListStrInput",
                        "expr_data_type": "dataTypeStr",
                        "field": "roles",
                        "input_data_type": "dataTypeListStr",
						"match_any": false,
                        "match_strategy": "fieldMatchExact",
                        "regex_enabled": false,
                        "values": [
                          "foobar"
                        ]
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "roles"
                    ],
                    "log_level": "info",
                    "log_enabled": true,
                    "match_all": true,
                    "rule_type": "aclRuleDenyWithInfoLoggerStop",
                    "tag": "rule0"
                  }
                ]
              }
			}`,
		},
		{
			name: "deny role foobar with email outside of specific email domain",
			config: []*RuleConfiguration{
				{
					Comment: "deny role foobar with email outside of @bar.foo",
					Conditions: []string{
						"no suffix match email @bar.foo",
						"match role foobar",
					},
					Action: `deny stop log`,
				},
				{
					Comment: "default allow",
					Conditions: []string{
						"match any",
					},
					Action: `allow stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"email": "jsmith@bar.foo",
				"roles": []string{"foobar"},
				"exp":   time.Now().Add(time.Duration(180) * time.Second).UTC().Unix(),
			},
			want: `{
              "allow": true,
              "config": {
                "count": 2,
                "rules": [
                  {
                    "action": "ruleActionDeny",
                    "comment": "deny role foobar with email outside of @bar.foo",
                    "conditions": [
                      {
                        "always_true": false,
                        "condition_type": "ruleStrCondSuffixNegativeMatchStrInput",
                        "expr_data_type": "dataTypeStr",
                        "field": "email",
                        "input_data_type": "dataTypeStr",
						"match_any": false,
                        "match_strategy": "fieldMatchSuffix",
                        "regex_enabled": false,
                        "values": [
                          "@bar.foo"
                        ]
                      },
                      {
                        "always_true": false,
                        "condition_type": "ruleStrCondExactMatchListStrInput",
                        "expr_data_type": "dataTypeStr",
                        "field": "roles",
                        "input_data_type": "dataTypeListStr",
						"match_any": false,
                        "match_strategy": "fieldMatchExact",
                        "regex_enabled": false,
                        "values": [
                          "foobar"
                        ]
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "email",
                      "roles"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleDenyWithInfoLoggerMatchAllStop",
                    "tag": "rule0"
                  },
                  {
                    "action": "ruleActionAllow",
                    "comment": "default allow",
                    "conditions": [
                      {
                        "always_true": true,
                        "condition_type": "ruleAnyCondAlwaysMatchAnyInput",
                        "expr_data_type": "dataTypeAny",
                        "field": "exp",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldMatchAlways",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "exp"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleAllowWithInfoLoggerStop",
                    "tag": "rule1"
                  }
                ]
              }
			}`,
		},
		{
			name: "allow when roles field exists, mutiple conditions, match all",
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"field roles exists",
						"suffix match email @bar.foo",
					},
					Action: `allow stop`,
				},
				{
					Comment: "default deny",
					Conditions: []string{
						"match any",
					},
					Action: `deny stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"email": "jsmith@bar.foo",
				"roles": []string{"foobar"},
				"exp":   time.Now().Add(time.Duration(180) * time.Second).UTC().Unix(),
			},
			want: `{
              "allow": true,
              "config": {
                "count": 2,
                "rules": [
                  {
                    "action": "ruleActionAllow",
                    "check_fields": {
                      "roles": true
                    },
                    "conditions": [
                      {
                        "always_true": false,
                        "condition_type": "ruleCondFieldFound",
                        "expr_data_type": "dataTypeAny",
                        "field": "roles",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldFound",
                        "regex_enabled": false
                      },
                      {
                        "always_true": false,
                        "condition_type": "ruleStrCondSuffixMatchStrInput",
                        "expr_data_type": "dataTypeStr",
                        "field": "email",
                        "input_data_type": "dataTypeStr",
						"match_any": false,
                        "match_strategy": "fieldMatchSuffix",
                        "regex_enabled": false,
                        "values": [
                          "@bar.foo"
                        ]
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "roles",
                      "email"
                    ],
                    "log_enabled": false,
                    "match_all": true,
                    "rule_type": "aclRuleFieldCheckAllowMatchAllStop"
                  },
                  {
                    "action": "ruleActionDeny",
                    "comment": "default deny",
                    "conditions": [
                      {
                        "always_true": true,
                        "condition_type": "ruleAnyCondAlwaysMatchAnyInput",
                        "expr_data_type": "dataTypeAny",
                        "field": "exp",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldMatchAlways",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "exp"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleDenyWithInfoLoggerStop",
                    "tag": "rule1"
                  }
                ]
              }
            }`,
		},
		{
			name: "allow when roles field exists, mutiple conditions, match any",
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"field roles exists",
						"suffix match email @bar.foo",
					},
					Action: `allow any stop`,
				},
				{
					Comment: "default deny",
					Conditions: []string{
						"match any",
					},
					Action: `deny stop log`,
				},
			},
			input: map[string]interface{}{
				"name": "John Smith",
				// "email": "jsmith@bar.foo",
				"roles": []string{"foobar"},
				"exp":   time.Now().Add(time.Duration(180) * time.Second).UTC().Unix(),
			},
			want: `{
              "allow": true,
              "config": {
                "count": 2,
                "rules": [
                  {
                    "action": "ruleActionAllow",
                    "check_fields": {
                      "roles": true
                    },
                    "conditions": [
                      {
                        "always_true": false,
                        "condition_type": "ruleCondFieldFound",
                        "expr_data_type": "dataTypeAny",
                        "field": "roles",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldFound",
                        "regex_enabled": false
                      },
                      {
                        "always_true": false,
                        "condition_type": "ruleStrCondSuffixMatchStrInput",
                        "expr_data_type": "dataTypeStr",
                        "field": "email",
                        "input_data_type": "dataTypeStr",
						"match_any": false,
                        "match_strategy": "fieldMatchSuffix",
                        "regex_enabled": false,
                        "values": [
                          "@bar.foo"
                        ]
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "roles",
                      "email"
                    ],
                    "log_enabled": false,
                    "match_all": false,
                    "rule_type": "aclRuleFieldCheckAllowMatchAnyStop"
                  },
                  {
                    "action": "ruleActionDeny",
                    "comment": "default deny",
                    "conditions": [
                      {
                        "always_true": true,
                        "condition_type": "ruleAnyCondAlwaysMatchAnyInput",
                        "expr_data_type": "dataTypeAny",
                        "field": "exp",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldMatchAlways",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "exp"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleDenyWithInfoLoggerStop",
                    "tag": "rule1"
                  }
                ]
              }
            }`,
		},
		{
			name: "allow when roles field exists and role matches",
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"field roles exists",
						"match role foobar",
					},
					Action: `allow stop`,
				},
				{
					Conditions: []string{
						"match any",
					},
					Action: `deny stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"email": "jsmith@bar.foo",
				"roles": []string{"foobar"},
				"exp":   time.Now().Add(time.Duration(180) * time.Second).UTC().Unix(),
			},
			shouldErr: true,
			err:       errors.ErrACLRuleSyntaxDuplicateField.WithArgs("roles"),
		},
		{
			name: "allow when roles field exists",
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"field roles exists",
					},
					Action: `allow stop`,
				},
				{
					Comment: "default deny",
					Conditions: []string{
						"match any",
					},
					Action: `deny stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"email": "jsmith@bar.foo",
				"roles": []string{"foobar"},
				"exp":   time.Now().Add(time.Duration(180) * time.Second).UTC().Unix(),
			},
			want: `{
              "allow": true,
              "config": {
                "count": 2,
                "rules": [
                  {
                    "action": "ruleActionAllow",
                    "conditions": [
                      {
                        "always_true": false,
                        "condition_type": "ruleCondFieldFound",
                        "expr_data_type": "dataTypeAny",
                        "field": "roles",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldFound",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "roles"
                    ],
					"check_fields": {
					  "roles": true
					},
                    "log_enabled": false,
                    "match_all": true,
                    "rule_type": "aclRuleFieldCheckAllowStop"
                  },
                  {
                    "action": "ruleActionDeny",
                    "comment": "default deny",
                    "conditions": [
                      {
                        "always_true": true,
                        "condition_type": "ruleAnyCondAlwaysMatchAnyInput",
                        "expr_data_type": "dataTypeAny",
                        "field": "exp",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldMatchAlways",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "exp"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleDenyWithInfoLoggerStop",
                    "tag": "rule1"
                  }
                ]
              }
            }`,
		},
		{
			name:     "allow when roles field does not exists",
			disabled: true,
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"field roles not exists",
					},
					Action: `allow stop log counter`,
				},
				{
					Comment: "default deny",
					Conditions: []string{
						"match any",
					},
					Action: `deny stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"email": "jsmith@bar.foo",
				"exp":   time.Now().Add(time.Duration(180) * time.Second).UTC().Unix(),
			},
			want: `{
              "allow": true,
              "config": {
                "count": 2,
                "rules": [
                  {
                    "action": "ruleActionAllow",
                    "check_fields": {
                      "roles": false
                    },
                    "conditions": [
                      {
                        "always_true": false,
                        "condition_type": "ruleCondFieldNotFound",
                        "expr_data_type": "dataTypeAny",
                        "field": "roles",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldNotFound",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": true,
                    "fields": [
                      "roles"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleFieldCheckAllowWithInfoLoggerCounterStop",
                    "tag": "rule0"
                  },
                  {
                    "action": "ruleActionDeny",
                    "comment": "default deny",
                    "conditions": [
                      {
                        "always_true": true,
                        "condition_type": "ruleAnyCondAlwaysMatchAnyInput",
                        "expr_data_type": "dataTypeAny",
                        "field": "exp",
                        "input_data_type": "dataTypeAny",
						"match_any": false,
                        "match_strategy": "fieldMatchAlways",
                        "regex_enabled": false
                      }
                    ],
                    "counter_enabled": false,
                    "fields": [
                      "exp"
                    ],
                    "log_enabled": true,
                    "log_level": "info",
                    "match_all": true,
                    "rule_type": "aclRuleDenyWithInfoLoggerStop",
                    "tag": "rule1"
                  }
                ]
              }
            }`,
		},
		{
			name:     "allow when metadata field exists",
			disabled: true,
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"field metadata exists",
					},
					Action: `allow stop`,
				},
			},
			input: map[string]interface{}{
				"metadata": map[string]interface{}{
					"foo": "bar",
				},
			},
			want: `{
            }`,
		},
		{
			name:     "allow when email is not in foo.bar domain",
			disabled: true,
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"no suffix match email @foo.bar",
					},
					Action: `allow stop`,
				},
			},
			input: map[string]interface{}{
				"email": "jsmith@bar.foo",
			},
			want: `{
            }`,
		},
		{
			name:     "allow when custom field foo equals to bar",
			disabled: true,
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"match foo bar",
					},
					Action: `allow stop`,
				},
			},
			input: map[string]interface{}{
				"foo": "bar",
			},
			want: `{
            }`,
		},
		{
			name:     "allow when exp field does not exceed 2 hours lifetime",
			disabled: true,
			config: []*RuleConfiguration{
				{
					Conditions: []string{
						"match expires_at less than 2 hours from now",
					},
					Action: `allow stop`,
				},
				{
					Conditions: []string{
						"match any",
					},
					Action: `deny stop`,
				},
			},
			input: map[string]interface{}{
				"exp": 0,
			},
			want: `{
            }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				t.SkipNow()
			}
			var err error
			ctx := context.Background()
			logger := logutil.NewLogger()
			accessList := NewAccessList()
			accessList.SetLogger(logger)
			if tc.defaultAllow {
				accessList.SetDefaultAllowAction()
			}
			err = accessList.AddRules(ctx, tc.config)
			if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
				return
			}
			got := make(map[string]interface{})
			got["config"] = tests.Unpack(t, accessList.AsMap())
			got["allow"] = accessList.Allow(ctx, tc.input)
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %s", tests.UnpackJSON(t, got))
				t.Errorf("NewPortal() rule mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
