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

// Package sqlite supplies bound JSON secret records from a private SQLite file.
package sqlite

import "github.com/greenpau/go-authcrunch/internal/sqlitedb"

// Config selects one record; secret values are runtime provisioning inputs.
type Config struct {
	Name    string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Path    string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Record  string `json:"record,omitempty" xml:"record,omitempty" yaml:"record,omitempty"`
	Timeout string `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// Validate normalizes defaults without reading files or retrieving secrets.
func (c *Config) Validate() error {
	if c == nil || !sqlitedb.ValidText(c.Name, 128) || !sqlitedb.ValidText(c.Record, 256) {
		return sqlitedb.ErrConfig
	}
	return sqlitedb.Normalize(&c.Path, &c.Timeout)
}
