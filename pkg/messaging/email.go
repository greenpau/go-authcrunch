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

// EmailProvider represents email messaging provider.
type EmailProvider struct {
	Name        string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Address     string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Protocol    string `json:"protocol,omitempty" xml:"protocol,omitempty" yaml:"protocol,omitempty"`
	Credentials string `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
}

// Validate validates EmailProvider configuration.
func (c *EmailProvider) Validate() error {
	if c.Name == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name")
	}
	if c.Credentials == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("credentials")
	}
	if c.Address == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("address")
	}
	if c.Protocol == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("protocol")
	}
	return nil
}
