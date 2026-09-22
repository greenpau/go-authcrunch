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

// Package parser decodes reusable password hashing configuration directives.
package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewPasswordHashConfigFromDirectives accepts an encoded block body with
// algorithm, cost (bcrypt), memory (Argon2 KiB), iterations and parallelism.
// Each setting takes exactly one value and may occur once. Empty input selects
// bcrypt cost 10. This function validates settings but does not hash passwords.
func NewPasswordHashConfigFromDirectives(statements []string) (*identity.PasswordHashConfig, error) {
	c := &identity.PasswordHashConfig{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := fmt.Errorf("invalid password hash directive at statement %d", i+1)
		if strings.ContainsAny(statement, "\r\n") {
			return nil, invalid
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) != 2 || args[1] == "" || seen[args[0]] {
			return nil, invalid
		}
		seen[args[0]] = true
		if args[0] == "algorithm" {
			c.Algorithm = args[1]
			continue
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n <= 0 {
			return nil, invalid
		}
		switch args[0] {
		case "cost":
			c.Cost = n
		case "memory":
			c.Memory = n
		case "iterations":
			c.Iterations = n
		case "parallelism":
			c.Parallelism = n
		default:
			return nil, invalid
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
