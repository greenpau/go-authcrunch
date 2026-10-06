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

// Package parser decodes HTTP JSON authorizer transport configuration.
package parser

import (
	"fmt"
	"strings"
	"unicode/utf8"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
)

// NewHTTPJSONAuthorizerConfigFromDirectives parses a complete encoded block body.
// endpoint is required; timeout defaults to 1s. Each setting occurs once. Parsing
// performs no I/O. Use cfgutil.EncodeArgs for values containing spaces.
func NewHTTPJSONAuthorizerConfigFromDirectives(statements []string) (*httpjson.Config, error) {
	c := &httpjson.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*httpjson.Config, error) {
			return nil, fmt.Errorf("invalid HTTP JSON authorizer directive at line %d", i+1)
		}
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) != 2 || strings.TrimSpace(args[1]) == "" || seen[args[0]] {
			return invalid()
		}
		seen[args[0]] = true
		switch args[0] {
		case "endpoint":
			c.Endpoint = args[1]
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
