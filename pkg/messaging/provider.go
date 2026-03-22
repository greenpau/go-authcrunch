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

// UnknownMessagingProviderKindLabel is the label for unknown  messaging provider type.
const UnknownMessagingProviderKindLabel = "unknown"

// Provider is an interface to work with messaging providers.
type Provider interface {
	Validate() error
	AsMap() map[string]any
	Kind() string
}

// NewProvider parses instructions and returns Provider.
func NewProvider(instructions []string) (Provider, error) {
	providerKind := UnknownMessagingProviderKindLabel
	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, errors.ErrMessagingMalformedInstructionThrown.WithArgs(err, instruction)
		}
		if args[0] == "kind" {
			providerKind = args[1]
		}
	}

	var provider Provider
	switch providerKind {
	case EmailMessagingProviderKindLabel:
		p, err := NewEmailProvider(instructions)
		if err != nil {
			return nil, err
		}
		provider = p
	case FileMessagingProviderKindLabel:
		p, err := NewFileProvider(instructions)
		if err != nil {
			return nil, err
		}
		provider = p
	default:
		return nil, errors.ErrMessagingUnsupportedKind.WithArgs(providerKind)
	}

	err := provider.Validate()
	return provider, err
}
