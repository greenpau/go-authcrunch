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

// GenericCredentialKindLabel is the label for GenericCredential type.
const GenericCredentialKindLabel = "generic"

// GenericCredential represents username and password credentials, with optional
// domain name field.
type GenericCredential struct {
	Name     string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Username string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Domain   string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
}

// NewGenericCredential parses instructions and returns GenericCredential.
func NewGenericCredential(instructions []string) (*GenericCredential, error) {
	cred := &GenericCredential{}

	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, errors.ErrCredMalformedInstructionThrown.WithArgs(err, instruction)
		}
		if len(args) != 2 {
			return nil, errors.ErrCredMalformedInstructionBadSyntax.WithArgs(instruction)
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
		case "kind":
			if args[1] != GenericCredentialKindLabel {
				return nil, errors.ErrCredMalformedInstructionKindMismatch.WithArgs(GenericCredentialKindLabel, args[1])
			}
		default:
			return nil, errors.ErrCredMalformedInstructionUnsupportedKey.WithArgs(instruction)
		}
	}
	err := cred.Validate()
	return cred, err
}

// Validate validates Generic credentials.
func (c *GenericCredential) Validate() error {
	if c.Name == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("name")
	}
	if c.Username == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("username")
	}
	if c.Password == "" {
		return errors.ErrCredKeyValueEmpty.WithArgs("password")
	}
	return nil
}

// AsMap returns credential config.
func (c *GenericCredential) AsMap() map[string]any {
	m := make(map[string]any)
	if c.Name != "" {
		m["name"] = c.Name
	}
	if c.Username != "" {
		m["username"] = c.Username
	}
	if c.Password != "" {
		m["password"] = c.Password
	}
	if c.Domain != "" {
		m["domain"] = c.Domain
	}
	m["kind"] = c.Kind()
	return m
}

// Kind returns credential kind.
func (c *GenericCredential) Kind() string {
	return GenericCredentialKindLabel
}
