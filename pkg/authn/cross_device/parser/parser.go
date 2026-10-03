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

// Package parser decodes cross-device login directives without a host dependency.
package parser

import (
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewCrossDeviceLoginConfigFromDirectives accepts complete encoded statements:
// "enable cross-device login" or "disable cross-device login". Collect all
// feature statements and encode each using cfgutil.EncodeArgs. Empty input
// disables the feature. Duplicate settings (including conflicting states),
// malformed records and unknown keywords fail without a partial result.
// Adapters must reject empty tokens before encoding them.
func NewCrossDeviceLoginConfigFromDirectives(statements []string) (*authn.CrossDeviceLoginConfig, error) {
	config := &authn.CrossDeviceLoginConfig{}
	for i, statement := range statements {
		if strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid cross-device login directive at line %d", i+1)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) != 3 || (args[0] != "enable" && args[0] != "disable") || args[1] != "cross-device" || args[2] != "login" {
			return nil, fmt.Errorf("invalid cross-device login directive at line %d", i+1)
		}
		if i > 0 {
			return nil, fmt.Errorf("duplicate cross-device login directive at line %d", i+1)
		}
		config.Enabled = args[0] == "enable"
	}
	return config, nil
}
