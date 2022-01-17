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

// Organization is an organized body of people with a particular purpose.
type Organization struct {
	ID      uint64   `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name    string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Aliases []string `json:"aliases,omitempty" xml:"aliases,omitempty" yaml:"aliases,omitempty"`
}

// NewOrganization returns an instance of Organization.
func NewOrganization() *Organization {
	return &Organization{}
}
