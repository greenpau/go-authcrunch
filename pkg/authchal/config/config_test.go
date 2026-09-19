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

package config_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authchal/config"
)

func TestAuthenticationChallengeConfig(t *testing.T) {
	for _, c := range []*config.AuthenticationChallengeConfig{nil, {}, {Rules: []*config.Rule{nil}}, {Rules: []*config.Rule{{}}}, {Rules: []*config.Rule{{Challenges: []string{"secret"}}}}, {Rules: []*config.Rule{{Challenges: []string{"u2f", "u2f"}}}}, {Rules: []*config.Rule{{Challenges: []string{"u2f"}, HasOr: true}}}, {Rules: []*config.Rule{{Challenges: []string{"u2f"}, Conditions: []string{"u2f"}}}}} {
		if c.Validate() == nil {
			t.Fatal("invalid typed policy accepted")
		}
	}
	c := &config.AuthenticationChallengeConfig{Rules: []*config.Rule{{Challenges: []string{"u2f", "totp"}, HasOr: true}}, Statements: []string{"u2f or totp"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := c.Clone()
	clone.Rules[0].Challenges[0] = "password"
	clone.Statements[0] = "password"
	if c.Rules[0].Challenges[0] != "u2f" || c.Statements[0] != "u2f or totp" {
		t.Fatal("clone aliases policy")
	}
	selected := c.ResolveChallenges(map[string]bool{"totp": true})
	if diff := cmp.Diff([]string{"totp"}, selected); diff != "" {
		t.Fatal(diff)
	}
	selected[0] = "changed"
	if c.Rules[0].Challenges[1] != "totp" {
		t.Fatal("selection aliases policy")
	}
}
