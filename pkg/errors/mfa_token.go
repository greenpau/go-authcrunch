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

// MFA token errors.
const (
	ErrAddMfaToken    StandardError = "failed adding MFA token: %v"
	ErrDeleteMfaToken StandardError = "failed deleting MFA token %q: %v"
	ErrGetMfaTokens   StandardError = "failed getting MFA tokens: %v"

	ErrDuplicateMfaTokenSecret  StandardError = "duplicate MFA token secret"
	ErrDuplicateMfaTokenComment StandardError = "duplicate MFA token comment"

	ErrMfaTokenEmptyAlgorithm   StandardError = "empty MFA token algorithm"
	ErrMfaTokenTypeEmpty        StandardError = "empty MFA token type"
	ErrMfaTokenInvalidType      StandardError = "invalid MFA token type: %s"
	ErrMfaTokenInvalidAlgorithm StandardError = "invalid MFA token algorithm: %s"
	ErrMfaTokenInvalidPeriod    StandardError = "invalid MFA token period: %d"
	ErrMfaTokenInvalidDigits    StandardError = "invalid MFA token digits: %d"
	ErrMfaTokenInvalidPasscode  StandardError = "invalid MFA token passcode: %v"

	ErrWebAuthnRegisterNotFound                          StandardError = "webauthn register not found"
	ErrWebAuthnChallengeNotFound                         StandardError = "webauthn challenge not found"
	ErrWebAuthnParse                                     StandardError = "failed parsing webauthn request: %v"
	ErrWebAuthnEmptyRegisterID                           StandardError = "webauthn register id is empty"
	ErrWebAuthnEmptyRegisterKeyType                      StandardError = "webauthn register key type is empty"
	ErrWebAuthnInvalidRegisterKeyType                    StandardError = "invalid webauthn register key type: %v"
	ErrWebAuthnEmptyRegisterTransport                    StandardError = "webauthn register key transport is empty"
	ErrWebAuthnInvalidRegisterTransport                  StandardError = "invalid webauthn register key transport: %v"
	ErrWebAuthnRegisterAttestationObjectNotFound         StandardError = "webauthn register attestation object not found"
	ErrWebAuthnRegisterAuthDataNotFound                  StandardError = "webauthn register attestation object auth data not found"
	ErrWebAuthnRegisterCredentialDataNotFound            StandardError = "webauthn register attestation object auth data credential not found"
	ErrWebAuthnRegisterEmptyRelyingPartyID               StandardError = "webauthn register attestation object auth data rpIdHash empty"
	ErrWebAuthnRegisterEmptyFlags                        StandardError = "webauthn register attestation object auth data flags empty"
	ErrWebAuthnRegisterPublicKeyNotFound                 StandardError = "webauthn register attestation object auth data credential public key not found"
	ErrWebAuthnRegisterPublicKeyUnsupported              StandardError = "webauthn register attestation object auth data credential public key type %v is unsupported"
	ErrWebAuthnRegisterPublicKeyTypeNotFound             StandardError = "webauthn register attestation object auth data credential public key type not found"
	ErrWebAuthnRegisterPublicKeyAlgorithmUnsupported     StandardError = "webauthn register attestation object auth data credential public key algorithm %v is unsupported"
	ErrWebAuthnRegisterPublicKeyAlgorithmNotFound        StandardError = "webauthn register attestation object auth data credential public key algorithm not found"
	ErrWebAuthnRegisterPublicKeyCurveUnsupported         StandardError = "webauthn register attestation object auth data credential public key curve_type %v is unsupported"
	ErrWebAuthnRegisterPublicKeyTypeAlgorithmUnsupported StandardError = "webauthn register attestation object auth data credential public key type %q and algorithm %q are unsupported"
	ErrWebAuthnRegisterPublicKeyParamNotFound            StandardError = "webauthn register attestation object auth data credential public key has type %q and algorithm %q, but %q not found"
	ErrWebAuthnRegisterPublicKeyCurveCoord               StandardError = "webauthn register attestation object auth data credential public key curve %v coordinate error: %v"
	ErrWebAuthnRegisterPublicKeyMaterial                 StandardError = "webauthn register attestation object auth data credential public key %q error: %v"
	ErrWebAuthnRequest                                   StandardError = "webauthn request failed: %v"
	ErrWebAuthnVerifyRequest                             StandardError = "webauthn authentication request failed: %v"
)
