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

// Package parser decodes host-independent Documents configuration directives.
package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewDocumentsAPIConfigFromDirectives accepts complete portal statements encoded
// with cfgutil.EncodeArgs. The API is disabled by default, including an empty
// list or storage-only settings. Explicitly use "enable documents api" or
// "disable documents api". Storage directives start with "documents api":
// database PATH, public origin URL, base path PATH, realms REALM...,
// max file bytes N, max user bytes N, max total bytes N, max user files N,
// max total files N, max keys N, max recipients N, upload ttl seconds N.
// Collect all statements before parsing; settings, including opposing enable
// directives, may occur only once. Adapters reject empty tokens before encoding.
// Apply the result with PortalConfig.ConfigureDocumentsAPI. Parsing performs no
// IO, validates required storage only when enabled, and never mutates inputs.
func NewDocumentsAPIConfigFromDirectives(statements []string) (*authn.DocumentsAPIConfig, error) {
	settings := &authn.DocumentsAPIConfig{Storage: &documents.Config{}}
	c := settings.Storage
	text := map[string]*string{"database": &c.Database, "public origin": &c.PublicOrigin, "base path": &c.BasePath}
	ints := map[string]*int64{"max file bytes": &c.MaxFileBytes, "max user bytes": &c.MaxUserBytes, "max total bytes": &c.MaxTotalBytes, "upload ttl seconds": &c.UploadTTLSeconds}
	seen := make(map[string]bool)
	for i, statement := range statements {
		invalid := func() (*authn.DocumentsAPIConfig, error) {
			return nil, fmt.Errorf("invalid documents directive at line %d", i+1)
		}
		if strings.ContainsAny(statement, "\r\n") {
			return invalid()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 {
			return invalid()
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return invalid()
			}
		}
		key := ""
		if args[0] == "enable" || args[0] == "disable" {
			if len(args) != 3 || args[1] != "documents" || args[2] != "api" {
				return invalid()
			}
			key, settings.Enabled = "state", args[0] == "enable"
		} else {
			if len(args) < 3 || args[0] != "documents" || args[1] != "api" {
				return invalid()
			}
			args = args[2:]
			switch args[0] {
			case "realms":
				if len(args) < 2 {
					return invalid()
				}
				key = "realms"
				c.Realms = append([]string(nil), args[1:]...)
			default:
				if len(args) < 2 {
					return invalid()
				}
				key = strings.Join(args[:len(args)-1], " ")
				if !slices.Equal(args[:len(args)-1], strings.Split(key, " ")) {
					return invalid()
				}
				value := args[len(args)-1]
				if target, ok := text[key]; ok {
					*target = value
				} else {
					n, err := strconv.ParseInt(value, 10, 64)
					if err != nil || n < 0 {
						return invalid()
					}
					if target, ok := ints[key]; ok {
						*target = n
					} else if key == "max user files" && n <= 100000 {
						c.MaxUserFiles = int(n)
					} else if key == "max total files" && n <= 1000000 {
						c.MaxTotalFiles = int(n)
					} else if key == "max keys" && n <= 1000000 {
						c.MaxKeys = int(n)
					} else if key == "max recipients" && n <= 1000 {
						c.MaxRecipients = int(n)
					} else {
						return invalid()
					}
				}
			}
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate documents directive at line %d", i+1)
		}
		seen[key] = true
	}
	if settings.Enabled {
		if err := c.Validate(); err != nil {
			return nil, err
		}
	}
	return settings, nil
}
