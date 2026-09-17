// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

// Profile contains optional, explicitly supplied standard OpenID identity attributes.
// Verification flags must reflect an actual ownership check by the identity store.
// Missing values are not synthesized or released as empty claims.
type Profile struct {
	GivenName           string   `json:"given_name,omitempty" xml:"given_name,omitempty" yaml:"given_name,omitempty"`
	FamilyName          string   `json:"family_name,omitempty" xml:"family_name,omitempty" yaml:"family_name,omitempty"`
	MiddleName          string   `json:"middle_name,omitempty" xml:"middle_name,omitempty" yaml:"middle_name,omitempty"`
	Nickname            string   `json:"nickname,omitempty" xml:"nickname,omitempty" yaml:"nickname,omitempty"`
	ProfileURL          string   `json:"profile,omitempty" xml:"profile,omitempty" yaml:"profile,omitempty"`
	Picture             string   `json:"picture,omitempty" xml:"picture,omitempty" yaml:"picture,omitempty"`
	Website             string   `json:"website,omitempty" xml:"website,omitempty" yaml:"website,omitempty"`
	Gender              string   `json:"gender,omitempty" xml:"gender,omitempty" yaml:"gender,omitempty"`
	Birthdate           string   `json:"birthdate,omitempty" xml:"birthdate,omitempty" yaml:"birthdate,omitempty"`
	Zoneinfo            string   `json:"zoneinfo,omitempty" xml:"zoneinfo,omitempty" yaml:"zoneinfo,omitempty"`
	Locale              string   `json:"locale,omitempty" xml:"locale,omitempty" yaml:"locale,omitempty"`
	PhoneNumber         string   `json:"phone_number,omitempty" xml:"phone_number,omitempty" yaml:"phone_number,omitempty"`
	PhoneNumberVerified *bool    `json:"phone_number_verified,omitempty" xml:"phone_number_verified,omitempty" yaml:"phone_number_verified,omitempty"`
	Address             *Address `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	UpdatedAt           int64    `json:"updated_at,omitempty" xml:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// Address is the structured postal address defined by OpenID Connect Core.
type Address struct {
	Formatted     string `json:"formatted,omitempty" xml:"formatted,omitempty" yaml:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty" xml:"street_address,omitempty" yaml:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty" xml:"locality,omitempty" yaml:"locality,omitempty"`
	Region        string `json:"region,omitempty" xml:"region,omitempty" yaml:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty" xml:"postal_code,omitempty" yaml:"postal_code,omitempty"`
	Country       string `json:"country,omitempty" xml:"country,omitempty" yaml:"country,omitempty"`
}

// Clone returns an independent copy suitable for an identity transaction callback.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	c := *p
	if p.PhoneNumberVerified != nil {
		c.PhoneNumberVerified = new(*p.PhoneNumberVerified)
	}
	if p.Address != nil {
		c.Address = new(*p.Address)
	}
	return &c
}
