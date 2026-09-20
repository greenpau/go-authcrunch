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

// Package state owns private, authenticated runtime state for independent
// AuthCrunch hosts. It has no HTTP server or container dependencies.
package state

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Config opts a runtime into persistence. A nil config keeps volatile behavior.
// Directory must be private local storage with reliable locking and atomic
// rename. Keep the entire directory, including its encryption key, together.
type Config struct {
	Directory string `json:"directory,omitempty" xml:"directory,omitempty" yaml:"directory,omitempty"`
}

// Validate checks configuration without creating files or generating keys.
func (c *Config) Validate() error {
	if c == nil || !filepath.IsAbs(c.Directory) || strings.ContainsAny(c.Directory, "\x00\r\n") || filepath.Clean(c.Directory) == string(filepath.Separator) {
		return fmt.Errorf("state directory must be an absolute non-root path")
	}
	c.Directory = filepath.Clean(c.Directory)
	return nil
}
