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

// Package parser parses the body of an AuthCrunch state block.
package parser

import (
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/state"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewStateConfigFromDirectives accepts exactly one encoded "directory PATH"
// statement. Omit the state configuration entirely to retain volatile behavior.
func NewStateConfigFromDirectives(statements []string) (*state.Config, error) {
	if len(statements) != 1 || strings.ContainsAny(statements[0], "\r\n") {
		return nil, fmt.Errorf("state requires exactly one directory statement")
	}
	args, err := cfgutil.DecodeArgs(statements[0])
	if err != nil || len(args) != 2 || args[0] != "directory" || args[1] == "" {
		return nil, fmt.Errorf("invalid state directory statement")
	}
	c := &state.Config{Directory: args[1]}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
