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

// Package parser decodes SQLite session and refresh storage configuration.
package parser

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
)

// NewSQLiteRefreshStorageConfigFromDirectives parses an encoded block body with
// path, max sessions, max rotations, and timeout settings, each occurring once.
// Path is required. Use cfgutil.EncodeArgs for paths with spaces. No I/O occurs.
func NewSQLiteRefreshStorageConfigFromDirectives(statements []string) (*sqlite.Config, error) {
	c := &sqlite.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*sqlite.Config, error) {
			return nil, fmt.Errorf("invalid SQLite refresh storage directive at line %d", i+1)
		}
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return invalid()
		}
		key := strings.Join(args[:len(args)-1], " ")
		value := args[len(args)-1]
		if value == "" || seen[key] {
			return invalid()
		}
		seen[key] = true
		switch {
		case len(args) == 2 && args[0] == "path":
			c.Path = value
		case len(args) == 2 && args[0] == "timeout":
			c.Timeout = value
		case len(args) == 3 && args[0] == "max" && (args[1] == "sessions" || args[1] == "rotations"):
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 {
				return invalid()
			}
			if args[1] == "sessions" {
				c.MaxSessions = n
			} else {
				c.MaxRotations = n
			}
		default:
			return invalid()
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
