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

// StoreCapabilities describes implemented operations, never authorization.
// False means unsupported, not an empty credential collection. Hosts must still
// validate the exact session and immutable identity for each operation.
type StoreCapabilities struct {
	ProfileRead         bool     `json:"profile_read" xml:"profile_read" yaml:"profile_read"`
	PasswordChange      bool     `json:"password_change" xml:"password_change" yaml:"password_change"`
	APIKeys             bool     `json:"api_keys" xml:"api_keys" yaml:"api_keys"`
	PublicKeys          bool     `json:"public_keys" xml:"public_keys" yaml:"public_keys"`
	MFA                 bool     `json:"mfa" xml:"mfa" yaml:"mfa"`
	AuthenticationFlows bool     `json:"authentication_flows" xml:"authentication_flows" yaml:"authentication_flows"`
	Connections         bool     `json:"connections" xml:"connections" yaml:"connections"`
	Documents           bool     `json:"documents" xml:"documents" yaml:"documents"`
	AdminOperations     []string `json:"admin_operations" xml:"admin_operations" yaml:"admin_operations"`
}

// StoreCapabilityProvider supplies a detached description of backend support.
// It does not replace IdentityRequestStore or transactional identity validation.
type StoreCapabilityProvider interface {
	GetCapabilities() StoreCapabilities
}
