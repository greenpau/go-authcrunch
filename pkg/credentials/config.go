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
	"fmt"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// Config represents a collection of various credentials.
type Config struct {
	RawCredentialConfigs [][]string `json:"raw_credential_configs,omitempty" xml:"raw_credential_configs,omitempty" yaml:"raw_credential_configs,omitempty"`
	Generic              []*Generic `json:"generic,omitempty" xml:"generic,omitempty" yaml:"generic,omitempty"`
}

// Credential is an interface to work with credentials.
type Credential interface {
	Validate() error
}

// Validate validates credentials
func (cfg *Config) Validate() error {
	genericCredentials := []*Generic{}
	for _, instructions := range cfg.RawCredentialConfigs {
		credRaw, err := NewCredential(instructions)
		if err != nil {
			return err
		}

		if err := credRaw.Validate(); err != nil {
			return err
		}

		switch cred := credRaw.(type) {
		case *Generic:
			genericCredentials = append(genericCredentials, cred)
		default:
			return errors.ErrCredAddConfigType.WithArgs(credRaw)
		}
	}

	cfg.Generic = genericCredentials
	return nil
}

// NewCredential parses instructions and returns Credential.
func NewCredential(instructions []string) (Credential, error) {
	cred := &Generic{}
	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, fmt.Errorf("malformed credential instruction: %v: %v", instruction, err)
		}
		if len(args) != 2 {
			return nil, fmt.Errorf("malformed credential instruction: %v: bad syntax", instruction)
		}
		switch args[0] {
		case "name":
			cred.Name = args[1]
		case "username":
			cred.Username = args[1]
		case "password":
			cred.Password = args[1]
		case "domain":
			cred.Domain = args[1]
		default:
			return nil, fmt.Errorf("malformed credential instruction: %v: unsupported key", instruction)
		}
	}
	err := cred.Validate()
	return cred, err
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
func (cfg *Config) ExtractGeneric(s string) *Generic {
	for _, c := range cfg.Generic {
		if c.Name == s {
			return c
		}
	}
	return nil
}
