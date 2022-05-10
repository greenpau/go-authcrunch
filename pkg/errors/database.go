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

// Database errors.
const (
	ErrNewDatabase                StandardError = "failed initializing database at %q: %v"
	ErrNewDatabaseInvalidUser     StandardError = "failed initializing database: found invalid user %v, %v"
	ErrNewDatabaseDuplicateUser   StandardError = "failed initializing database: found duplicate user %s %v"
	ErrNewDatabaseDuplicateUserID StandardError = "failed initializing database: found duplicate user id %s %v"
	ErrNewDatabaseDuplicateEmail  StandardError = "failed initializing database: found duplicate email address %s, %v"
	ErrNewDatabaseDuplicateAPIKey StandardError = "failed initializing database: found duplicate api key %s, %v"

	ErrDatabaseCommit       StandardError = "failed database commit to %q: %v"
	ErrDatabaseOperation    StandardError = "database operation failed: %v"
	ErrDatabaseInvalidUser  StandardError = "username and email point to a different identity in the database"
	ErrDatabaseUserNotFound StandardError = "user not found"
	// ErrDatabaseInvalidUserPassword StandardError = "invalid password"
	ErrAuthFailed StandardError = "user authentication failed: %v"

	ErrAddPublicKey    StandardError = "failed adding %s public key: %v"
	ErrDeletePublicKey StandardError = "failed deleting %q key: %v"
	ErrGetPublicKeys   StandardError = "failed getting %q keys: %v"

	ErrAddAPIKey    StandardError = "failed adding %s key: %v"
	ErrDeleteAPIKey StandardError = "failed deleting %q key: %v"
	ErrGetAPIKeys   StandardError = "failed getting %q keys: %v"

	ErrChangeUserPassword   StandardError = "failed change user password: %v"
	ErrUpdateUserPassword   StandardError = "failed updating user password: %v"
	ErrUserPasswordNotFound StandardError = "user password not set"
	ErrUserPasswordInvalid  StandardError = "user password is invalid"

	ErrUserPolicyCompliance     StandardError = "username policy compliance check failed"
	ErrPasswordPolicyCompliance StandardError = "user password policy compliance check failed"

	ErrAddUser    StandardError = "failed adding user %q: %v"
	ErrDeleteUser StandardError = "failed deleting user %q: %v"
	ErrGetUsers   StandardError = "failed retrieving users: %v"
	ErrGetUser    StandardError = "failed retrieving user %q: %v"

	ErrPasswordEmpty                StandardError = "empty password"
	ErrPasswordEmptyAlgorithm       StandardError = "empty password hash algorithm"
	ErrPasswordGenerate             StandardError = "password generation error: %v"
	ErrPasswordUnsupportedAlgorithm StandardError = "unsupported password hash algorithm: %v"
	ErrPasswordHashed               StandardError = "failed handling hashed password: %v"

	ErrUserIDInvalidLength StandardError = "invalid user id length: %d"
	ErrUsernameEmpty       StandardError = "username is empty"

	ErrEmailAddressInvalid StandardError = "invalid email address"
	ErrRoleEmpty           StandardError = "role name is empty"

	ErrParseNameFailed StandardError = "failed to parse name: %s"

	ErrCreditCardUnsupportedIssuer      StandardError = "unsupported credit card issuer: %v"
	ErrCreditCardUnsupportedAssociation StandardError = "unsupported credit card association: %v"
)
