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

// Config represents a collection of various credentials.
type Config struct {
	Email   []*SMTP    `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Generic []*Generic `json:"generic,omitempty" xml:"generic,omitempty" yaml:"generic,omitempty"`
}

// Add adds a credential to Config.
func (cfg *Config) Add(i interface{}) error {
	switch v := i.(type) {
	case *SMTP:
		cfg.Email = append(cfg.Email, v)
	case *Generic:
		cfg.Generic = append(cfg.Generic, v)
	default:
		return errors.ErrCredAddConfigType.WithArgs(v)
	}
	return nil
}
