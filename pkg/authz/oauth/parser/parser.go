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

// Package parser decodes direct OAuth authorization policy statements.
package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authz"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewOAuthAuthorizationConfigFromDirectives parses complete statements:
// use oauth identity provider NAME; oauth public origin URL; oauth base path PATH;
// oauth session cookie name NAME; oauth login cookie name NAME;
// oauth session lifetime SECONDS; oauth maximum sessions N;
// oauth maximum pending logins N. Collect the entire subject before parsing.
// Empty statements return nil (disabled). Errors never return partial config or
// echo input. The caller owns tokenization and encodes with cfgutil.EncodeArgs.
func NewOAuthAuthorizationConfigFromDirectives(policyName string, statements []string) (*authz.OAuthAuthorizationConfig, error) {
	if len(statements) == 0 {
		return nil, nil
	}
	c := &authz.OAuthAuthorizationConfig{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		fail := func() (*authz.OAuthAuthorizationConfig, error) {
			return nil, fmt.Errorf("invalid or duplicate OAuth authorization statement %d", i+1)
		}
		if strings.ContainsAny(statement, "\r\n") {
			return fail()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return fail()
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return fail()
			}
		}
		key := strings.Join(args[:len(args)-1], " ")
		if seen[key] {
			return fail()
		}
		seen[key] = true
		value := args[len(args)-1]
		// Joining is only for keyword selection. The full token count below rejects
		// quoted multiword keywords; values preserve their original boundaries.
		switch {
		case key == "use oauth identity provider" && len(args) == 5:
			c.IdentityProvider = value
		case key == "oauth public origin" && len(args) == 4:
			c.PublicOrigin = value
		case key == "oauth base path" && len(args) == 4:
			c.BasePath = value
		case key == "oauth session cookie name" && len(args) == 5:
			c.SessionCookieName = value
		case key == "oauth login cookie name" && len(args) == 5:
			c.LoginCookieName = value
		case key == "oauth session lifetime" && len(args) == 4:
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return fail()
			}
			c.SessionLifetime = n
		case key == "oauth maximum sessions" && len(args) == 4:
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return fail()
			}
			c.MaxSessions = n
		case key == "oauth maximum pending logins" && len(args) == 5:
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return fail()
			}
			c.MaxPendingLogins = n
		default:
			return fail()
		}
	}
	if err := c.Validate(policyName); err != nil {
		return nil, err
	}
	return c, nil
}
