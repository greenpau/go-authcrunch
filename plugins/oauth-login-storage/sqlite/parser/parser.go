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

// Package parser decodes SQLite OAuth login storage configuration.
package parser

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
)

// NewSQLiteOAuthLoginStoreConfigFromDirectives parses a complete body of encoded
// "path PATH", optional "timeout DURATION" and "capacity COUNT" statements.
// No I/O occurs. Empty bodies, duplicate settings and unknown fields fail.
func NewSQLiteOAuthLoginStoreConfigFromDirectives(statements []string) (*sqlite.Config, error) {
	c := &sqlite.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*sqlite.Config, error) {
			return nil, fmt.Errorf("invalid SQLite OAuth login storage directive at line %d", i+1)
		}
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) != 2 || args[1] == "" || seen[args[0]] {
			return invalid()
		}
		seen[args[0]] = true
		switch args[0] {
		case "path":
			c.Path = args[1]
		case "timeout":
			c.Timeout = args[1]
		case "capacity":
			c.Capacity, err = strconv.Atoi(args[1])
			if err != nil || c.Capacity < 1 {
				return invalid()
			}
		default:
			return invalid()
		}
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite OAuth login storage configuration")
	}
	return c, nil
}
