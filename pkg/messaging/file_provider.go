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
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// FileMessagingProviderKindLabel is the label for file messaging provider type.
const FileMessagingProviderKindLabel = "file"

// FileProvider represents file messaging provider which writes messages
// to a local file system,
type FileProvider struct {
	Name            string            `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	RootDir         string            `json:"root_dir,omitempty" xml:"root_dir,omitempty" yaml:"root_dir,omitempty"`
	SenderEmail     string            `json:"sender_email,omitempty" xml:"sender_email,omitempty" yaml:"sender_email,omitempty"`
	SenderName      string            `json:"sender_name,omitempty" xml:"sender_name,omitempty" yaml:"sender_name,omitempty"`
	Templates       map[string]string `json:"templates,omitempty" xml:"templates,omitempty" yaml:"templates,omitempty"`
	BlindCarbonCopy []string          `json:"blind_carbon_copy,omitempty" xml:"blind_carbon_copy,omitempty" yaml:"blind_carbon_copy,omitempty"`
}

// NewFileProvider parses instructions and returns FileProvider.
func NewFileProvider(instructions []string) (*FileProvider, error) {
	provider := &FileProvider{}

	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, errors.ErrMessagingMalformedInstructionThrown.WithArgs(err, instruction)
		}
		switch args[0] {
		case "name":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Name = args[1]
		case "root_dir":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.RootDir = args[1]
		case "template":
			if len(args) != 3 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			if provider.Templates == nil {
				provider.Templates = make(map[string]string)
			}
			provider.Templates[args[1]] = args[2]
		case "sender":
			if len(args) != 2 && len(args) != 3 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.SenderEmail = args[1]
			if len(args) == 3 {
				provider.SenderName = args[2]
			}
		case "kind":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			if args[1] != FileMessagingProviderKindLabel {
				return nil, errors.ErrMessagingMalformedInstructionKindMismatch.WithArgs(FileMessagingProviderKindLabel, args[1])
			}
		case "bcc":
			if len(args) < 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			for _, arg := range args[1:] {
				provider.BlindCarbonCopy = append(provider.BlindCarbonCopy, arg)
			}

		default:
			return nil, errors.ErrMessagingMalformedInstructionUnsupportedKey.WithArgs(instruction)
		}
	}
	err := provider.Validate()
	return provider, err
}

// Validate validates FileProvider configuration.
func (p *FileProvider) Validate() error {
	if p.Name == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name")
	}

	if p.RootDir == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("root_dir")
	}

	if p.SenderEmail == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("sender_email")
	}

	if p.Templates != nil {
		for k := range p.Templates {
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

// AsMap returns credential config.
func (p *FileProvider) AsMap() map[string]any {
	m := make(map[string]any)
	if p.Name != "" {
		m["name"] = p.Name
	}
	if p.RootDir != "" {
		m["root_dir"] = p.RootDir
	}
	if p.SenderEmail != "" {
		m["sender_email"] = p.SenderEmail
	}
	if p.SenderName != "" {
		m["sender_name"] = p.SenderName
	}
	if p.Templates != nil {
		m["templates"] = p.Templates
	}
	if len(p.BlindCarbonCopy) > 0 {
		m["bcc"] = p.BlindCarbonCopy
	}
	m["kind"] = p.Kind()
	return m
}

// Kind returns credential kind.
func (p *FileProvider) Kind() string {
	return FileMessagingProviderKindLabel
}
