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
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const passwordlessKeyword = "passwordless"

// Config represents a collection of various messaging providers.
type Config struct {
	// providers contains caller-owned runtime injections; bind before concurrent use.
	providers      map[string]Provider
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
	count := len(cfg.providers)
	for _, provider := range cfg.providers {
		if err := provider.Validate(); err != nil {
			return fmt.Errorf("invalid injected messaging provider")
		}
	}

	for _, instructions := range cfg.RawConfigs {
		providerRaw, err := NewProvider(instructions)
		if err != nil {
			return err
		}

		switch provider := providerRaw.(type) {
		case *EmailProvider:
			if _, exists := cfg.providers[provider.Name]; exists {
				return fmt.Errorf("duplicate messaging provider name")
			}
			emailProviders = append(emailProviders, provider)
			count++
		case *FileProvider:
			if _, exists := cfg.providers[provider.Name]; exists {
				return fmt.Errorf("duplicate messaging provider name")
			}
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
	if cfg == nil {
		return false
	}
	if _, ok := cfg.providers[s]; ok {
		return true
	}
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
	if cfg == nil {
		return UnknownMessagingProviderKindLabel
	}
	if provider := cfg.providers[s]; provider != nil {
		return provider.Kind()
	}
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
	if cfg == nil {
		return nil
	}
	if provider := cfg.providers[s]; provider != nil {
		return provider
	}
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

// AddProvider binds an already constructed, caller-owned messaging backend.
// Runtime bindings are excluded from serialization. Call Validate after binding
// all providers and before publishing the configuration; no concurrent mutation
// or automatic backend Close is performed. Built-in kinds retain their factories.
func (cfg *Config) AddProvider(name string, provider Provider) error {
	if cfg == nil || provider == nil || name == "" || len(name) > 128 || strings.TrimSpace(name) != name || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		return fmt.Errorf("invalid messaging provider binding")
	}
	if cfg.FindProvider(name) {
		return fmt.Errorf("duplicate messaging provider name")
	}
	if err := provider.Validate(); err != nil {
		return fmt.Errorf("invalid injected messaging provider")
	}
	kind := provider.Kind()
	if kind == "" || kind == EmailMessagingProviderKindLabel || kind == FileMessagingProviderKindLabel || kind == UnknownMessagingProviderKindLabel {
		return fmt.Errorf("reserved messaging provider kind")
	}
	if cfg.providers == nil {
		cfg.providers = make(map[string]Provider)
	}
	cfg.providers[name] = provider
	return nil
}
