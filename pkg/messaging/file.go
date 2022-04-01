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

package messaging

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// FileProvider represents file messaging provider which writes messages
// to a local file system,
type FileProvider struct {
	Name      string            `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	RootDir   string            `json:"root_dir,omitempty" xml:"root_dir,omitempty" yaml:"root_dir,omitempty"`
	Templates map[string]string `json:"templates,omitempty" xml:"templates,omitempty" yaml:"templates,omitempty"`
}

// Validate validates FileProvider configuration.
func (e *FileProvider) Validate() error {
	if e.Name == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name")
	}

	if e.RootDir == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("root_dir")
	}

	if e.Templates != nil {
		for k := range e.Templates {
			switch k {
			case "password_recovery":
			case "registration_confirmation":
			case "registration_ready":
			case "registration_verdict":
			case "mfa_otp":
			default:
				return errors.ErrMessagingProviderInvalidTemplate.WithArgs(k)
			}
		}
	}
	return nil
}
