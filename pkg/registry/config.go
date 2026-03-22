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

package registry

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// Config represents a collection of user registration providers.
type Config struct {
	RawConfigs     [][]string                   `json:"raw_configs,omitempty" xml:"raw_configs,omitempty" yaml:"raw_configs,omitempty"`
	LocalProviders []*LocalUserRegistryProvider `json:"local_providers,omitempty" xml:"local_providers,omitempty" yaml:"local_providers,omitempty"`
}

// GetProviders returns all providers.
func (cfg *Config) GetProviders() []Provider {
	providers := []Provider{}
	for _, lp := range cfg.LocalProviders {
		providers = append(providers, lp)
	}
	return providers
}

// Add adds provider config to Config.
func (cfg *Config) Add(instructions []string) {
	cfg.RawConfigs = append(cfg.RawConfigs, instructions)
}

// Validate validates credentials
func (cfg *Config) Validate() error {
	localProviders := []*LocalUserRegistryProvider{}
	count := 0

	for _, instructions := range cfg.RawConfigs {
		providerRaw, err := NewProvider(instructions)
		if err != nil {
			return err
		}

		switch provider := providerRaw.(type) {
		case *LocalUserRegistryProvider:
			localProviders = append(localProviders, provider)
			count++
		}
	}

	if count < 1 {
		return errors.ErrUserRegistryConfigEmpty.WithArgs()
	}

	cfg.LocalProviders = localProviders
	return nil
}

// // FindProvider search for Provider by name.
// func (cfg *Config) FindProvider(s string) bool {
// 	for _, p := range cfg.EmailProviders {
// 		if p.Name == s {
// 			return true
// 		}
// 	}
// 	for _, p := range cfg.FileProviders {
// 		if p.Name == s {
// 			return true
// 		}
// 	}
// 	return false
// }

// // FindProviderCredentials search for Provider by name and then identifies
// // the credentials used by the provider.
// func (cfg *Config) FindProviderCredentials(s string) string {
// 	for _, p := range cfg.EmailProviders {
// 		if p.Name == s {
// 			if p.Passwordless {
// 				return passwordlessKeyword
// 			}
// 			return p.Credentials
// 		}
// 	}
// 	return ""
// }

// // GetProviderType returns type of a messaging provider.
// func (cfg *Config) GetProviderType(s string) string {
// 	for _, p := range cfg.EmailProviders {
// 		if p.Name == s {
// 			return EmailMessagingProviderKindLabel
// 		}
// 	}
// 	for _, p := range cfg.FileProviders {
// 		if p.Name == s {
// 			return FileMessagingProviderKindLabel
// 		}
// 	}

// 	return UnknownMessagingProviderKindLabel
// }

// // ExtractEmailProvider returns EmailProvider by name.
// func (cfg *Config) ExtractEmailProvider(s string) *EmailProvider {
// 	for _, p := range cfg.EmailProviders {
// 		if p.Name == s {
// 			return p
// 		}
// 	}
// 	return nil
// }

// // ExtractFileProvider returns FileProvider by name.
// func (cfg *Config) ExtractFileProvider(s string) *FileProvider {
// 	for _, p := range cfg.FileProviders {
// 		if p.Name == s {
// 			return p
// 		}
// 	}
// 	return nil
// }

// // ExtractProvider returns Provider by name.
// func (cfg *Config) ExtractProvider(s string) Provider {
// 	var provider Provider
// 	for _, p := range cfg.EmailProviders {
// 		if p.Name == s {
// 			provider = p
// 		}
// 	}
// 	for _, p := range cfg.FileProviders {
// 		if p.Name == s {
// 			provider = p
// 		}
// 	}
// 	return provider
// }

// // SetCredentials binds to shared credentials.
// func (cfg *UserRegistryConfig) SetCredentials(c *credentials.Config) {
// 	cfg.credentials = c
// }

// // SetMessaging binds to messaging config.
// func (cfg *UserRegistryConfig) SetMessaging(c *messaging.Config) {
// 	cfg.messaging = c
// }

// // ValidateMessaging validates messaging provider and credentials used for
// // the user registration.
// func (cfg *UserRegistryConfig) ValidateMessaging() error {
// 	if cfg.messaging == nil {
// 		return errors.ErrUserRegistryConfigMessagingNil.WithArgs(cfg.Name)
// 	}
// 	if found := cfg.messaging.FindProvider(cfg.EmailProvider); !found {
// 		return errors.ErrUserRegistryConfigMessagingProviderNotFound.WithArgs(cfg.Name)
// 	}

// 	providerType := cfg.messaging.GetProviderType(cfg.EmailProvider)

// 	if providerType == "email" {
// 		providerCreds := cfg.messaging.FindProviderCredentials(cfg.EmailProvider)
// 		if providerCreds == "" {
// 			return errors.ErrUserRegistryConfigMessagingProviderCredentialsNotFound.WithArgs(cfg.Name, cfg.EmailProvider)
// 		}

// 		if providerCreds != "passwordless" {
// 			if cfg.credentials == nil {
// 				return errors.ErrUserRegistryConfigCredentialsNil.WithArgs(cfg.Name)
// 			}
// 			if found := cfg.credentials.FindCredential(providerCreds); !found {
// 				return errors.ErrUserRegistryConfigCredentialsNotFound.WithArgs(cfg.Name, providerCreds)
// 			}
// 		}
// 	}
// 	return nil
// }
