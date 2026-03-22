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

// EmailMessagingProviderKindLabel is the label for email messaging provider type.
const EmailMessagingProviderKindLabel = "email"

// EmailProvider represents email messaging provider.
type EmailProvider struct {
	Name            string            `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Address         string            `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Protocol        string            `json:"protocol,omitempty" xml:"protocol,omitempty" yaml:"protocol,omitempty"`
	Credentials     string            `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	SenderEmail     string            `json:"sender_email,omitempty" xml:"sender_email,omitempty" yaml:"sender_email,omitempty"`
	SenderName      string            `json:"sender_name,omitempty" xml:"sender_name,omitempty" yaml:"sender_name,omitempty"`
	Templates       map[string]string `json:"templates,omitempty" xml:"templates,omitempty" yaml:"templates,omitempty"`
	Passwordless    bool              `json:"passwordless,omitempty" xml:"passwordless,omitempty" yaml:"passwordless,omitempty"`
	BlindCarbonCopy []string          `json:"blind_carbon_copy,omitempty" xml:"blind_carbon_copy,omitempty" yaml:"blind_carbon_copy,omitempty"`
}

// NewEmailProvider parses instructions and returns EmailProvider.
func NewEmailProvider(instructions []string) (*EmailProvider, error) {
	provider := &EmailProvider{}

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
		case "address":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Address = args[1]
		case "protocol":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Protocol = args[1]
		case "credentials":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Credentials = args[1]
		case "sender":
			if len(args) != 2 && len(args) != 3 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.SenderEmail = args[1]
			if len(args) == 3 {
				provider.SenderName = args[2]
			}
		case "bcc":
			if len(args) < 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			for _, arg := range args[1:] {
				provider.BlindCarbonCopy = append(provider.BlindCarbonCopy, arg)
			}
		case "passwordless":
			provider.Passwordless = true
		case "template":
			if len(args) != 3 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			if provider.Templates == nil {
				provider.Templates = make(map[string]string)
			}
			provider.Templates[args[1]] = args[2]
		case "kind":
			if len(args) != 2 {
				return nil, errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			if args[1] != EmailMessagingProviderKindLabel {
				return nil, errors.ErrMessagingMalformedInstructionKindMismatch.WithArgs(EmailMessagingProviderKindLabel, args[1])
			}
		default:
			return nil, errors.ErrMessagingMalformedInstructionUnsupportedKey.WithArgs(instruction)
		}
	}
	err := provider.Validate()
	return provider, err
}

// Validate validates EmailProvider configuration.
func (p *EmailProvider) Validate() error {
	if p.Name == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name")
	}

	switch {
	case p.Credentials != "" && p.Passwordless:
		return errors.ErrMessagingProviderCredentialsWithPasswordless
	case p.Credentials == "" && !p.Passwordless:
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("credentials")
	}

	if p.Address == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("address")
	}

	switch p.Protocol {
	case "smtp":
	case "smtps":
	case "":
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("protocol")
	default:
		return errors.ErrMessagingProviderProtocolUnsupported.WithArgs(p.Protocol)
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
func (p *EmailProvider) AsMap() map[string]any {
	m := make(map[string]any)
	if p.Name != "" {
		m["name"] = p.Name
	}
	if p.Address != "" {
		m["address"] = p.Address
	}
	if p.Protocol != "" {
		m["protocol"] = p.Protocol
	}
	if p.Credentials != "" {
		m["credentials"] = p.Credentials
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
	m["passwordless"] = p.Passwordless
	if len(p.BlindCarbonCopy) > 0 {
		m["bcc"] = p.BlindCarbonCopy
	}
	m["kind"] = p.Kind()
	return m
}

// Kind returns credential kind.
func (p *EmailProvider) Kind() string {
	return EmailMessagingProviderKindLabel
}
