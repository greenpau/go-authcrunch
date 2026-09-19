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

package authchal

import (
	"github.com/greenpau/go-authcrunch/pkg/authchal/config"
	"github.com/greenpau/go-authcrunch/pkg/authchal/parser"
)

// Ruleset is an ordered authentication challenge policy.
type Ruleset = config.AuthenticationChallengeConfig

// NewRuleset preserves the encoded rule-body API. New configuration consumers
// should use parser.NewAuthenticationChallengeConfigFromDirectives directly.
func NewRuleset(statements []string) (*Ruleset, error) {
	return parser.NewAuthenticationChallengeConfigFromDirectives(statements)
}
