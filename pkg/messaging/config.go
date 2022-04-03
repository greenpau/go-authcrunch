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
	FileProviders  []*FileProvider  `json:"file_providers,omitempty" xml:"file_providers,omitempty" yaml:"file_providers,omitempty"`
}

// Provider is an interface to work with messaging providers.
type Provider interface {
	Validate() error
}

// Add adds a messaging provider to Config.
func (cfg *Config) Add(c Provider) error {
	switch v := c.(type) {
	case *EmailProvider:
	case *FileProvider:
	default:
		return errors.ErrMessagingAddProviderConfigType.WithArgs(v)
	}

	if err := c.Validate(); err != nil {
		return err
	}

	switch v := c.(type) {
	case *EmailProvider:
		cfg.EmailProviders = append(cfg.EmailProviders, v)
	case *FileProvider:
		cfg.FileProviders = append(cfg.FileProviders, v)
	}
	return nil
}

// FindProvider search for Provider by name.
func (cfg *Config) FindProvider(s string) bool {
	for _, p := range cfg.EmailProviders {
		if p.Name == s {
			return true
		}
	}
	for _, p := range cfg.FileProviders {
		if p.Name == s {
			return true
		}
	}
	return false
}

// FindProviderCredentials search for Provider by name and then identifies
// the credentials used by the provider.
func (cfg *Config) FindProviderCredentials(s string) string {
	for _, p := range cfg.EmailProviders {
		if p.Name == s {
			if p.Passwordless {
				return "passwordless"
			}
			return p.Credentials
		}
	}
	return ""
}

// GetProviderType returns type of a messaging provider.
func (cfg *Config) GetProviderType(s string) string {
	for _, p := range cfg.EmailProviders {
		if p.Name == s {
			return "email"
		}
	}
	for _, p := range cfg.FileProviders {
		if p.Name == s {
			return "file"
		}
	}

	return "unknown"
}

// ExtractEmailProvider returns EmailProvider by name.
func (cfg *Config) ExtractEmailProvider(s string) *EmailProvider {
	for _, p := range cfg.EmailProviders {
		if p.Name == s {
			return p
		}
	}
	return nil
}

// ExtractFileProvider returns FileProvider by name.
func (cfg *Config) ExtractFileProvider(s string) *FileProvider {
	for _, p := range cfg.FileProviders {
		if p.Name == s {
			return p
		}
	}
	return nil
}
