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

// Location repsents a location, e.g. street address.
type Location struct {
	Street      string `json:"street,omitempty" xml:"street,omitempty" yaml:"street,omitempty"`
	City        string `json:"city,omitempty" xml:"city,omitempty" yaml:"city,omitempty"`
	State       string `json:"state,omitempty" xml:"state,omitempty" yaml:"state,omitempty"`
	ZipCode     string `json:"zip_code,omitempty" xml:"zip_code,omitempty" yaml:"zip_code,omitempty"`
	Confirmed   bool   `json:"confirmed,omitempty" xml:"confirmed,omitempty" yaml:"confirmed,omitempty"`
	Current     bool   `json:"current,omitempty" xml:"current,omitempty" yaml:"current,omitempty"`
	Domicile    bool   `json:"domicile,omitempty" xml:"domicile,omitempty" yaml:"domicile,omitempty"`
	Residential bool   `json:"residential,omitempty" xml:"residential,omitempty" yaml:"residential,omitempty"`
	Commercial  bool   `json:"commercial,omitempty" xml:"commercial,omitempty" yaml:"commercial,omitempty"`
}

// NewLocation returns an instance of Location.
func NewLocation() *Location {
	return &Location{}
}
