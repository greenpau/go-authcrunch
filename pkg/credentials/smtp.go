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

package credentials

import (
	"github.com/greenpau/aaasf/pkg/errors"
)

// SMTP represents SMTP credentials.
type SMTP struct {
	Name     string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Username string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Address  string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Protocol string `json:"protocol,omitempty" xml:"protocol,omitempty" yaml:"protocol,omitempty"`
}

// Validate validates SMTP credentials.
func (c *SMTP) Validate() error {
	if c.Name == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("name")
	}
	if c.Username == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("username")
	}
	if c.Password == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("password")
	}
	if c.Address == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("address")
	}
	if c.Protocol == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("protocol")
	}
	return nil
}
