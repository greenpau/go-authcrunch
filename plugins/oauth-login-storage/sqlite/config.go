// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

// Package sqlite provides transactional OAuth login storage for clients sharing
// one private local SQLite file. It is a reference adapter, not a multi-host
// database. PKCE evidence is stored in plaintext; protect the file and backups.
package sqlite

import "github.com/greenpau/go-authcrunch/internal/sqlitedb"

// Config selects a dedicated private database. All clients must agree on capacity.
type Config struct {
	Path     string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Timeout  string `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
	Capacity int    `json:"capacity,omitempty" xml:"capacity,omitempty" yaml:"capacity,omitempty"`
}

// Validate installs defaults without filesystem or network access.
func (c *Config) Validate() error {
	if c == nil {
		return sqlitedb.ErrConfig
	}
	if c.Capacity == 0 {
		c.Capacity = 10000
	}
	if c.Capacity < 1 || c.Capacity > 100000 {
		return sqlitedb.ErrConfig
	}
	return sqlitedb.Normalize(&c.Path, &c.Timeout)
}
