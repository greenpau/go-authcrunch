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

import "github.com/greenpau/go-authcrunch/pkg/errors"

// Config represents a collection of various credentials.
type Config struct {
	RawCredentialConfigs [][]string           `json:"raw_credential_configs,omitempty" xml:"raw_credential_configs,omitempty" yaml:"raw_credential_configs,omitempty"`
	Generic              []*GenericCredential `json:"generic,omitempty" xml:"generic,omitempty" yaml:"generic,omitempty"`
}

// Validate validates credentials
func (cfg *Config) Validate() error {
	genericCredentials := []*GenericCredential{}
	count := 0
	for _, instructions := range cfg.RawCredentialConfigs {
		credRaw, err := NewCredential(instructions)
		if err != nil {
			return err
		}

		switch cred := credRaw.(type) {
		case *GenericCredential:
			genericCredentials = append(genericCredentials, cred)
			count++
		}
	}

	if count < 1 {
		return errors.ErrCredConfigEmpty.WithArgs()
	}

	cfg.Generic = genericCredentials
	return nil
}

// Add adds a credential config to Config.
func (cfg *Config) Add(instructions []string) {
	cfg.RawCredentialConfigs = append(cfg.RawCredentialConfigs, instructions)
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
func (cfg *Config) ExtractGeneric(s string) *GenericCredential {
	for _, c := range cfg.Generic {
		if c.Name == s {
			return c
		}
	}
	return nil
}
