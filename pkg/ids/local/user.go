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

package local

// User holds the configuration for the identity store user.
type User struct {
	Username                 string   `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	EmailAddress             string   `json:"email_address,omitempty" xml:"email_address,omitempty" yaml:"email_address,omitempty"`
	Name                     string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Roles                    []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
	Password                 string   `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	PasswordOverwriteEnabled bool     `json:"password_overwrite_enabled,omitempty" xml:"password_overwrite_enabled,omitempty" yaml:"password_overwrite_enabled,omitempty"`
}
