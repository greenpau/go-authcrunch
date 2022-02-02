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
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// Config represents a collection of various credentials.
type Config struct {
	Generic []*Generic `json:"generic,omitempty" xml:"generic,omitempty" yaml:"generic,omitempty"`
}

// Credential is an interface to work with credentials.
type Credential interface {
	Validate() error
}

// Add adds a credential to Config.
func (cfg *Config) Add(c Credential) error {
	switch v := c.(type) {
	case *Generic:
	default:
		return errors.ErrCredAddConfigType.WithArgs(v)
	}

	if err := c.Validate(); err != nil {
		return err
	}

	switch v := c.(type) {
	case *Generic:
		cfg.Generic = append(cfg.Generic, v)
	}
	return nil
}

// FindCredential search for Credential by name.
func (cfg *Config) FindCredential(s string) bool {
	for _, c := range cfg.Generic {
		if c.Name == s {
			return true
		}
	}
	return false
}

// ExtractGeneric returns Generic credentials by name.
func (cfg *Config) ExtractGeneric(s string) *Generic {
	for _, c := range cfg.Generic {
		if c.Name == s {
			return c
		}
	}
	return nil
}
