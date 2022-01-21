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

package injector

import (
	"fmt"
	"strings"
)

// Config contains the entry for the HTTP header injection.
type Config struct {
	Header string `json:"header,omitempty" xml:"header,omitempty" yaml:"header,omitempty"`
	Field  string `json:"field,omitempty" xml:"field,omitempty" yaml:"field,omitempty"`
}

// Validate validates Config
func (c *Config) Validate() error {
	c.Header = strings.TrimSpace(c.Header)
	c.Field = strings.TrimSpace(c.Field)
	if c.Header == "" {
		return fmt.Errorf("undefined header name")
	}
	if c.Field == "" {
		return fmt.Errorf("undefined field name")
	}
	return nil
}
