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

// Package sqlite stores refresh families in a local transactional SQLite database.
package sqlite

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Config defines a dedicated local database. Its parent directory must already
// exist with private permissions. All clients of a database must use the same
// capacity and rotation limits. Timeout limits context-aware work and lock waits;
// filesystem calls and an in-progress SQLite commit can outlast that budget.
type Config struct {
	Path         string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	MaxSessions  int    `json:"max_sessions,omitempty" xml:"max_sessions,omitempty" yaml:"max_sessions,omitempty"`
	MaxRotations int    `json:"max_rotations,omitempty" xml:"max_rotations,omitempty" yaml:"max_rotations,omitempty"`
	Timeout      string `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// Validate normalizes defaults without filesystem access.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("SQLite refresh storage config is required")
	}
	if !validText(c.Path, 4096) || !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) == string(filepath.Separator) {
		return fmt.Errorf("SQLite refresh storage requires an absolute file path")
	}
	c.Path = filepath.Clean(c.Path)
	if c.MaxSessions == 0 {
		c.MaxSessions = 10000
	}
	if c.MaxRotations == 0 {
		c.MaxRotations = 1024
	}
	if c.MaxSessions < 1 || c.MaxSessions > 100000 || c.MaxRotations < 1 || c.MaxRotations > 100000 {
		return fmt.Errorf("SQLite refresh storage limits must be within 1-100000")
	}
	if c.Timeout == "" {
		c.Timeout = "1s"
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil || d < time.Millisecond || d > 30*time.Second {
		return fmt.Errorf("SQLite refresh storage timeout must be within 1ms-30s")
	}
	return nil
}

func validText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
