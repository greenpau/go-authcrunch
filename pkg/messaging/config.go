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

const passwordlessKeyword = "passwordless"

// Config represents a collection of various messaging providers.
type Config struct {
	RawConfigs     [][]string       `json:"raw_configs,omitempty" xml:"raw_configs,omitempty" yaml:"raw_configs,omitempty"`
	EmailProviders []*EmailProvider `json:"email_providers,omitempty" xml:"email_providers,omitempty" yaml:"email_providers,omitempty"`
	FileProviders  []*FileProvider  `json:"file_providers,omitempty" xml:"file_providers,omitempty" yaml:"file_providers,omitempty"`
}

// Add adds a messaging provider config to Config.
func (cfg *Config) Add(instructions []string) {
	cfg.RawConfigs = append(cfg.RawConfigs, instructions)
}

// Validate validates credentials
func (cfg *Config) Validate() error {
	emailProviders := []*EmailProvider{}
	fileProviders := []*FileProvider{}
	count := 0

	for _, instructions := range cfg.RawConfigs {
		providerRaw, err := NewProvider(instructions)
		if err != nil {
			return err
		}

		switch provider := providerRaw.(type) {
		case *EmailProvider:
			emailProviders = append(emailProviders, provider)
			count++
		case *FileProvider:
			fileProviders = append(fileProviders, provider)
			count++
		}
	}

	if count < 1 {
		return errors.ErrMessagingConfigEmpty.WithArgs()
	}

	cfg.EmailProviders = emailProviders
	cfg.FileProviders = fileProviders
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
				return passwordlessKeyword
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
			return EmailMessagingProviderKindLabel
		}
	}
	for _, p := range cfg.FileProviders {
		if p.Name == s {
			return FileMessagingProviderKindLabel
		}
	}

	return UnknownMessagingProviderKindLabel
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

// ExtractProvider returns Provider by name.
func (cfg *Config) ExtractProvider(s string) Provider {
	var provider Provider
	for _, p := range cfg.EmailProviders {
		if p.Name == s {
			provider = p
		}
	}
	for _, p := range cfg.FileProviders {
		if p.Name == s {
			provider = p
		}
	}
	return provider
}
