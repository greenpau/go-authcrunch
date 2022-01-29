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

// Config represents a collection of various messaging providers.
type Config struct {
	EmailProviders []*EmailProvider `json:"email_providers,omitempty" xml:"email_providers,omitempty" yaml:"email_providers,omitempty"`
}

// Provider is an interface to work with messaging providers.
type Provider interface {
	Validate() error
}

// Add adds a messaging provider to Config.
func (cfg *Config) Add(c Provider) error {
	switch v := c.(type) {
	case *EmailProvider:
	default:
		return errors.ErrMessagingAddProviderConfigType.WithArgs(v)
	}

	if err := c.Validate(); err != nil {
		return err
	}

	switch v := c.(type) {
	case *EmailProvider:
		cfg.EmailProviders = append(cfg.EmailProviders, v)
	}
	return nil
}
