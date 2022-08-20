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

package identity

import (
	"regexp"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

var emailRegex *regexp.Regexp

func init() {
	emailRegex = regexp.MustCompile(
		"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]" +
			"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9]" +
			"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
	)
}

// EmailAddress is an instance of email address
type EmailAddress struct {
	Address   string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Confirmed bool   `json:"confirmed,omitempty" xml:"confirmed,omitempty" yaml:"confirmed,omitempty"`
	Domain    string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
	isPrimary bool
}

// NewEmailAddress returns an instance of EmailAddress.
func NewEmailAddress(s string) (*EmailAddress, error) {
	if !emailRegex.MatchString(s) {
		return nil, errors.ErrEmailAddressInvalid
	}
	parts := strings.Split(s, "@")
	addr := &EmailAddress{
		Address: s,
		Domain:  parts[1],
	}
	return addr, nil
}

// Primary returns true is the email is a primary email.
func (m *EmailAddress) Primary() bool {
	if m.isPrimary {
		return true
	}
	return false
}

// ToString returns string representation of an email address.
func (m *EmailAddress) ToString() string {
	return m.Address
}
