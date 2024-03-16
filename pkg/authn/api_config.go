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

package authn

// APIConfig holds the configuration for API endpoints.
type APIConfig struct {
	ProfileEnabled bool `json:"profile_enabled,omitempty" xml:"profile_enabled,omitempty" yaml:"profile_enabled,omitempty"`
	AdminEnabled   bool `json:"admin_enabled,omitempty" xml:"admin_enabled,omitempty" yaml:"admin_enabled,omitempty"`
}
