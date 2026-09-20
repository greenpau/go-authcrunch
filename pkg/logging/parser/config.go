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

// Package parser decodes the body of an AuthCrunch logging block.
package parser

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/logging"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewLoggingConfigFromDirectives parses encoded block-body statements with the
// grammar "skip <exact|partial|prefix|suffix|regex> text <value>". Encode each
// tokenized statement with cfgutil.EncodeArgs; reject empty tokens before encoding.
// No header or braces are accepted. Repeated rules are additive (logical OR),
// including harmless duplicates. An empty block skips nothing. Errors return no
// partial configuration and do not echo input.
func NewLoggingConfigFromDirectives(statements []string) (*logging.Config, error) {
	c := &logging.Config{}
	for i, statement := range statements {
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) != 4 || !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid logging directive at line %d", i+1)
		}
		if args[0] != "skip" || args[2] != "text" {
			return nil, fmt.Errorf("unsupported logging directive at line %d", i+1)
		}
		c.Skip = append(c.Skip, logging.SkipRule{Match: args[1], Text: args[3]})
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
