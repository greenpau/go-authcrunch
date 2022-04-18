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

// Identity Provider Errors
const (
	ErrIdentityProviderConfigInvalid StandardError = "invalid identity provider config: %v"

	// Generic Errors.
	ErrIdentityProviderRequest StandardError = "%s failed: %v"

	// Config Errors.
	ErrIdentityProviderConfigureEmptyConfig    StandardError = "identity provider configuration is empty"
	ErrIdentityProviderConfigureLoggerNotFound StandardError = "identity provider configuration has no logger"
	ErrIdentityProviderConfigureNameEmpty      StandardError = "identity provider configuration has empty name"
	ErrIdentityProviderConfigureRealmEmpty     StandardError = "identity provider configuration has empty realm"
	ErrIdentityProviderNewConfig               StandardError = "identity provider config %v error: %v"
	ErrIdentityProviderConfig                  StandardError = "identity provider config error: %v"

	// OAuth Errors.
	ErrIdentityProviderOauthAuthorizationStateNotFound   StandardError = "OAuth 2.0 authorization state not found"
	ErrIdentityProviderOauthAuthorizationFailedDetailed  StandardError = "failed OAuth 2.0 authorization flow, error: %s, description: %s"
	ErrIdentityProviderOauthAuthorizationFailed          StandardError = "failed OAuth 2.0 authorization flow, error: %s"
	ErrIdentityProviderOauthFetchAccessTokenFailed       StandardError = "failed fetching OAuth 2.0 access token: %s"
	ErrIdentityProviderOauthFetchClaimsFailed            StandardError = "failed fetching OAuth 2.0 claims: %s"
	ErrIdentityProviderOauthFetchUserInfoFailed          StandardError = "failed fetching OAuth 2.0 user info: %v"
	ErrIdentityProviderOauthFetchUserGroupsFailed        StandardError = "failed fetching OAuth 2.0 user groups: %v"
	ErrIdentityProviderOauthValidateAccessTokenFailed    StandardError = "failed validating OAuth 2.0 access token: %s"
	ErrIdentityProviderOauthResponseProcessingFailed     StandardError = "unable to process OAuth 2.0 response"
	ErrIdentityProviderOauthGetAccessTokenFailedDetailed StandardError = "failed obtaining OAuth 2.0 access token, error: %v, description: %q"

	ErrIdentityProviderOauthKeyFetchFailed           StandardError = "failed to fetch jwt keys for OAuth 2.0 authorization server: %s"
	ErrIdentityProviderOauthMetadataFieldNotFound    StandardError = "metadata %s field not found for provider %s"
	ErrIdentityProviderOauthJwksResponseKeysNotFound StandardError = "jwks response has no keys field"
	ErrIdentityProviderOauthJwksKeysParseFailed      StandardError = "failed to compile jwks keys into JSON: %v"
	ErrIdentityProviderOauthJwksKeysNotFound         StandardError = "no jwks keys found"
	ErrIdentityProviderOauthJwksKeysTooManyAttempts  StandardError = "too many attemps to fetch jwks keys"

	ErrIdentityProviderOauthJwksInvalidKey                    StandardError = "invalid jwks key: %v"
	ErrIdentityProviderOAuthAccessTokenNotFound               StandardError = "OAuth 2.0 %s not found"
	ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported StandardError = "OAuth 2.0 %s signed with unsupported algorithm: %v"
	ErrIdentityProviderOAuthAccessTokenKeyIDNotFound          StandardError = "OAuth 2.0 kid not found in %s"
	ErrIdentityProviderOAuthAccessTokenKeyIDNotRegistered     StandardError = "OAuth 2.0 %s has unregisted key id %v"
	ErrIdentityProviderOAuthParseToken                        StandardError = "OAuth 2.0 failed to parse %s: %v"

	ErrIdentityProviderOAuthInvalidToken          StandardError = "OAuth 2.0 %s is invalid: %v"
	ErrIdentityProviderOAuthNonceValidationFailed StandardError = "OAuth 2.0 %s nonce claim validation failed: %v"
	ErrIdentityProviderOAuthEmailNotFound         StandardError = "OAuth 2.0 %s email claim not found"

	ErrIdentityProviderOauthMetadataFetchFailed                 StandardError = "failed to fetch metadata for OAuth 2.0 authorization server: %s"
	ErrIdentityProviderOauthGetAccessTokenFailed                StandardError = "failed obtaining OAuth 2.0 access token, error: %v"
	ErrIdentityProviderAuthorizationServerResponseFieldNotFound StandardError = "authorization server response has no %q field"
)
