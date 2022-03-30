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

package errors

// Identity Store Errors
const (
	ErrIdentityStoreConfigInvalid StandardError = "invalid identity store config: %v"

	// Local identity store errors.
	ErrIdentityStoreLocalConfigurePathEmpty    StandardError = "identity store configuration has empty database path"
	ErrIdentityStoreLocalConfigurePathMismatch StandardError = "identity store configuration database path does not match to an existing path in the same realm: %v %v"

	// LDAP identity store errors.
	ErrIdentityStoreLdapAuthenticateInvalidUserEmail StandardError = "LDAP authentication request contains invalid user email"
	ErrIdentityStoreLdapAuthenticateInvalidUsername  StandardError = "LDAP authentication request contains invalid username"
	ErrIdentityStoreLdapAuthenticateInvalidPassword  StandardError = "LDAP authentication request contains invalid password"
	ErrIdentityStoreLdapAuthFailed                   StandardError = "LDAP authentication failed: %v"

	// Generic Errors.
	ErrIdentityStoreRequest StandardError = "%s failed: %v"

	// Config Errors.
	ErrIdentityStoreConfigureEmptyConfig       StandardError = "identity store configuration is empty"
	ErrIdentityStoreConfigureLoggerNotFound    StandardError = "identity store configuration has no logger"
	ErrIdentityStoreInvalidProvider            StandardError = "identity store configuration has invalid provider: %s"
	ErrIdentityStoreConfigureNameEmpty         StandardError = "identity store configuration has empty name"
	ErrIdentityStoreConfigureRealmEmpty        StandardError = "identity store configuration has empty realm"
	ErrIdentityStoreNewConfig                  StandardError = "identity store config %v error: %v"
	ErrIdentityStoreNewConfigInvalidAuthMethod StandardError = "identity store config %v has invalid auth method"
	ErrIdentityStoreConfigureInvalidBaseURL    StandardError = "identity store config %q has invalid base auth url %q: %v"

	// Authentication Errors.
	ErrIdentityStoreLocalAuthFailed StandardError = "local backed authentication failed: %v"
)
