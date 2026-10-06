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

// Package parser decodes static claims enrichment configurations.
package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static"
)

// NewStaticClaimsEnrichmentConfigFromDirectives parses a block body containing
// claim <name> <value> statements encoded with cfgutil.EncodeArgs. Names must be
// unique; each value is a literal string. For other JSON types (or empty strings),
// use claim <name> json <JSON value>, with the complete JSON value in one token.
// The block header and braces are omitted; numbers preserve their JSON spelling.
func NewStaticClaimsEnrichmentConfigFromDirectives(statements []string) (*static.Config, error) {
	c := &static.Config{Claims: make(map[string]any)}
	for i, statement := range statements {
		invalid := func() (*static.Config, error) {
			return nil, fmt.Errorf("invalid static claims directive at line %d", i+1)
		}
		// encoding/json otherwise replaces invalid UTF-8 with U+FFFD, silently
		// changing literal values and potentially collapsing object keys.
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || (len(args) != 3 && len(args) != 4) || args[0] != "claim" {
			return invalid()
		}
		if _, exists := c.Claims[args[1]]; exists {
			return invalid()
		}
		if len(args) == 3 {
			c.Claims[args[1]] = args[2]
			continue
		}
		if args[2] != "json" || len(args[3]) > 64<<10 {
			return invalid()
		}
		decoder := json.NewDecoder(strings.NewReader(args[3]))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return invalid()
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return invalid()
		}
		c.Claims[args[1]] = value
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
