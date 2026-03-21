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
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// Credential is an interface to work with credentials.
type Credential interface {
	Validate() error
	AsMap() map[string]any
	Kind() string
}

// NewCredential parses instructions and returns Credential.
func NewCredential(instructions []string) (Credential, error) {
	credKind := GenericCredentialKindLabel
	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, errors.ErrCredMalformedInstructionThrown.WithArgs(err, instruction)
		}
		if len(args) != 2 {
			return nil, errors.ErrCredMalformedInstructionBadSyntax.WithArgs(instruction)

		}
		if args[0] == "kind" {
			credKind = args[1]
		}
	}

	var cred Credential
	switch credKind {
	case GenericCredentialKindLabel:
		gc, err := NewGenericCredential(instructions)
		if err != nil {
			return nil, err
		}
		cred = gc
	default:
		return nil, errors.ErrCredUnsupportedKind.WithArgs(credKind)
	}

	err := cred.Validate()
	return cred, err
}
