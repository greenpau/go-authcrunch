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

package acl

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// Keep this regression independent of the generated test matrices. Exercise
// the generated action, logging, counter, stop and field-check variants.
func TestACLUnconditionalRules(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		for _, stop := range []bool{false, true} {
			for _, counter := range []bool{false, true} {
				for _, level := range []string{"", "debug", "info", "warn", "error"} {
					for _, tc := range []struct {
						name       string
						conditions []string
						data       map[string]any
						any        bool
						match      bool
					}{
						{"single absent", []string{"match any"}, nil, false, true},
						{"single present", []string{"match any"}, map[string]any{"exp": int64(1)}, false, true},
						{"single null", []string{"match any"}, map[string]any{"exp": nil}, false, true},
						{"all", []string{"match any", "match roles admin"}, map[string]any{"roles": []string{"admin"}}, false, true},
						{"all missing role", []string{"match any", "match roles admin"}, nil, false, false},
						{"all negative missing role", []string{"match any", "no match roles blocked"}, nil, false, false},
						{"all wrong role", []string{"match roles admin", "match any"}, map[string]any{"roles": []string{"guest"}}, false, false},
						{"any missing role", []string{"match roles admin", "match any"}, nil, true, true},
						{"any wrong role", []string{"match any", "match roles admin"}, map[string]any{"roles": []string{"guest"}}, true, true},
						{"all field check", []string{"match any", "field email exists"}, map[string]any{"email": "user@example.com"}, false, true},
						{"all missing field", []string{"match any", "field email exists"}, nil, false, false},
						{"any field check", []string{"match any", "field email not exists"}, nil, true, true},
						{"any forbidden field", []string{"match any", "field email not exists"}, map[string]any{"email": "user@example.com"}, true, false},
					} {
						t.Run(fmt.Sprintf("%s/stop=%t/counter=%t/log=%s/%s", action, stop, counter, level, tc.name), func(t *testing.T) {
							core, logs := observer.New(zap.DebugLevel)
							directive := action
							if tc.any {
								directive += " any"
							}
							if stop {
								directive += " stop"
							}
							if counter {
								directive += " counter"
							}
							if level != "" {
								directive += " log " + level + " tag unconditional"
							}
							rule, err := newACLRule(t.Context(), 0, &RuleConfiguration{Conditions: tc.conditions, Action: directive}, zap.New(core))
							if err != nil {
								t.Fatal(err)
							}
							want := ruleVerdictContinue
							if tc.match {
								if action == "allow" {
									want = ruleVerdictAllow
									if stop {
										want = ruleVerdictAllowStop
									}
								} else {
									want = ruleVerdictDeny
									if stop {
										want = ruleVerdictDenyStop
									}
								}
							}
							for call := range 2 {
								if got := rule.eval(t.Context(), tc.data); got != want {
									t.Fatalf("eval() = %v, want %v", got, want)
								}
								entries := logs.TakeAll()
								if !tc.match || level == "" {
									continue
								}
								if len(entries) != 1 || entries[0].Message != "acl rule hit" || entries[0].Level.String() != level {
									t.Fatalf("unexpected rule hit logs: %v", entries)
								}
								fields := entries[0].ContextMap()
								if fields["action"] != action || fields["tag"] != "unconditional" {
									t.Fatalf("unexpected action/tag: %v", fields)
								}
								if counter && fields["counter"] != uint64(call+1) {
									t.Fatalf("hit counter = %v, want %d", fields["counter"], call+1)
								}
							}
						})
					}
				}
			}
		}
	}
}
