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

package authn

// CrossDeviceLoginConfig enables short-lived, explicitly approved browser login
// transfers. Omitted, nil and zero configurations disable this feature.
// Assign the result of cross_device/parser.NewCrossDeviceLoginConfigFromDirectives
// to PortalConfig.CrossDeviceLogin before constructing a portal.
type CrossDeviceLoginConfig struct {
	Enabled bool `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
}
