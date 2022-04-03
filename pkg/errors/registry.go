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

// Registry errors.
const (
	// User Registration errors
	ErrUserRegistrationConfig              StandardError = "user registration configuration for %q instance failed: %v"
	ErrUserRegistryConfigureLoggerNotFound StandardError = "user registry has no logger"

	ErrUserRegistryConfigMessagingNil                         StandardError = "user registration config %q messaging is nil"
	ErrUserRegistryConfigMessagingProviderNotFound            StandardError = "user registration config %q messaging provider %q not found"
	ErrUserRegistryConfigMessagingProviderCredentialsNotFound StandardError = "user registration config %q messaging provider %q has no associated credentials"
	ErrUserRegistryConfigCredentialsNil                       StandardError = "user registration config %q credentials is nil"
	ErrUserRegistryConfigCredentialsNotFound                  StandardError = "user registration config %q credential %q not found"
	ErrUserRegistryConfigAdminEmailNotFound                   StandardError = "user registration config %q registration admin email not found"
)
