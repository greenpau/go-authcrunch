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
	"time"
)

// Registration is an instance of user registration.
// Typically used in scenarios where user wants to
// register for a service. The user provides identity information
// and waits for an approval.
type Registration struct {
	ID         string    `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty" xml:"approved_at,omitempty" yaml:"approved_at,omitempty"`
	Approved   bool      `json:"approved,omitempty" xml:"approved,omitempty" yaml:"approved,omitempty"`
	DeclinedAt time.Time `json:"declined_at,omitempty" xml:"declined_at,omitempty" yaml:"declined_at,omitempty"`
	Declined   bool      `json:"declined,omitempty" xml:"declined,omitempty" yaml:"declined,omitempty"`
}

// NewRegistration returns an instance of Registration.
func NewRegistration(s string) *Registration {
	r := &Registration{
		ID:        s,
		CreatedAt: time.Now().UTC(),
	}
	return r
}

// Approve approves the Registration.
func (r *Registration) Approve() {
	r.Approved = true
	r.ApprovedAt = time.Now().UTC()
}

// Decline declines the Registration.
func (r *Registration) Decline() {
	r.Declined = true
	r.DeclinedAt = time.Now().UTC()
}
