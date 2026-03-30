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

package authproxy

// RealmAuthProxyConfig is auth proxy config for a realm.
type RealmAuthProxyConfig struct {
	PortalName        string `json:"portal_name,omitempty" xml:"portal_name,omitempty" yaml:"portal_name,omitempty"`
	BasicAuthEnabled  bool   `json:"basic_auth_enabled,omitempty" xml:"basic_auth_enabled,omitempty" yaml:"basic_auth_enabled,omitempty"`
	APIKeyAuthEnabled bool   `json:"api_key_auth_enabled,omitempty" xml:"api_key_auth_enabled,omitempty" yaml:"api_key_auth_enabled,omitempty"`
	IsRemote          bool   `json:"is_remote,omitempty" xml:"is_remote,omitempty" yaml:"is_remote,omitempty"`
	RemoteAddr        string `json:"remote_addr,omitempty" xml:"remote_addr,omitempty" yaml:"remote_addr,omitempty"`
	authenticator     Authenticator
	hasAuthenticator  bool
}

// NewRealmAuthProxyConfig returns an instance of RealmAuthProxyConfig.
func NewRealmAuthProxyConfig() *RealmAuthProxyConfig {
	return &RealmAuthProxyConfig{}
}

// HasAuthenticator returns true if there is an authenticator associated with the realm.
func (cfg *RealmAuthProxyConfig) HasAuthenticator() bool {
	return cfg.hasAuthenticator
}

// AddAuthenticator adds authenticator associated with the realm.
func (cfg *RealmAuthProxyConfig) AddAuthenticator(authenticator Authenticator) {
	cfg.authenticator = authenticator
	cfg.hasAuthenticator = true
}
