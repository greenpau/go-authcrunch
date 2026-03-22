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
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// UnknownUserRegistryProviderKindLabel is the label for unknown user registration provider type.
const UnknownUserRegistryProviderKindLabel = "unknown"

// Provider is an interface to work with user registration providers.
type Provider interface {
	Validate() error
	Activate(*zap.Logger) error
	AsMap() map[string]any
	Kind() string
	SetCredentials(*credentials.Config) error
	SetMessaging(*messaging.Config) error

	GetName() string

	AddUser(*requests.Request) error
	GetRegistrationEntry(string) (map[string]string, error)
	DeleteRegistrationEntry(string) error
	AddRegistrationEntry(string, map[string]string) error

	GetUsernamePolicyRegex() string
	GetUsernamePolicySummary() string
	GetPasswordPolicyRegex() string
	GetPasswordPolicySummary() string

	GetTitle() string
	GetCode() string
	GetRequireAcceptTerms() bool
	GetTermsConditionsLink() string
	GetPrivacyPolicyLink() string

	GetEmailProvider() string
	GetRequireDomainMX() bool
	GetDomainRestrictions() []string
	GetAdminEmails() []string

	Notify(map[string]string) error
	GetIdentityStoreName() string
	GetRealmName() string
	SetRealmName(string)
}

// NewProvider parses instructions and returns Provider.
func NewProvider(instructions []string) (Provider, error) {
	providerKind := UnknownUserRegistryProviderKindLabel
	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, errors.ErrUserRegistryConfigMalformedInstructionThrown.WithArgs(err, instruction)
		}
		if args[0] == "kind" {
			providerKind = args[1]
		}
	}

	var provider Provider
	switch providerKind {
	case LocalUserRegistryProviderKindLabel:
		p, err := NewLocalUserRegistryProvider(instructions)
		if err != nil {
			return nil, err
		}
		provider = p
	default:
		return nil, errors.ErrUserRegistryConfigUnsupportedKind.WithArgs(providerKind)
	}

	err := provider.Validate()
	return provider, err
}
