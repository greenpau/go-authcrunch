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

// Package parser decodes SQLite identity store backend configuration.
package parser

import (
	"fmt"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	"strings"
	"unicode/utf8"
)

// NewSQLiteIdentityStoreConfigFromDirectives parses name, path, realm and timeout.
func NewSQLiteIdentityStoreConfigFromDirectives(statements []string) (*sqlite.Config, error) {
	c := &sqlite.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*sqlite.Config, error) {
			return nil, fmt.Errorf("invalid SQLite identity store directive at line %d", i+1)
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
		case "name":
			c.Name = args[1]
		case "path":
			c.Path = args[1]
		case "realm":
			c.Realm = args[1]
		case "timeout":
			c.Timeout = args[1]
		default:
			return invalid()
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
