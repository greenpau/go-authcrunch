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

// Package parser decodes local identity attachment directives for any external backend.
package parser

import (
	"fmt"
	"slices"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewIdentityAttachmentConfigFromDirectives accepts complete encoded directives:
// attach to local identity store <name>. Empty input selects private memory.
// Pass all attachment statements together; duplicate declarations are rejected.
func NewIdentityAttachmentConfigFromDirectives(statements []string) (*attachment.Config, error) {
	config := &attachment.Config{}
	if len(statements) > 1 {
		return nil, fmt.Errorf("duplicate identity attachment directive")
	}
	for _, statement := range statements {
		if strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid identity attachment directive")
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) != 6 || !slices.Equal(args[:5], []string{"attach", "to", "local", "identity", "store"}) || args[5] == "" {
			return nil, fmt.Errorf("expected attach to local identity store with one name")
		}
		config.LocalIdentityStore = args[5]
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
