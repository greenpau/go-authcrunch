// Copyright 2020 Paul Greenberg greenpau@outlook.com
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
	"time"
)

// Registration is an instance of user registration.
// Typically used in scenarios where user wants to
// register for a service. The user provides identity information
// and waits for an approval.
type Registration struct {
	User     *User     `json:"user,omitempty" xml:"user,omitempty" yaml:"user,omitempty"`
	Created  time.Time `json:"created,omitempty" xml:"created,omitempty" yaml:"created,omitempty"`
	Aprroved bool      `json:"aprroved,omitempty" xml:"aprroved,omitempty" yaml:"aprroved,omitempty"`
}

// NewRegistration returns an instance of Registration.
func NewRegistration(user *User) *Registration {
	r := &Registration{
		User:    user,
		Created: time.Now().UTC(),
	}
	return r
}
