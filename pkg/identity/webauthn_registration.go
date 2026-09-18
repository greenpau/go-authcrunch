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

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// ValidateWebAuthnRegistration validates a WebAuthn creation response's
// bindings against trusted server expectations before constructing its MFA
// token. It does not verify the authenticator's attestation statement.
func ValidateWebAuthnRegistration(r *requests.Request) (*MfaToken, error) {
	if r == nil {
		return nil, errors.ErrWebAuthnRequest.WithArgs("registration request is nil")
	}
	if r.MfaToken.Type != "u2f" {
		return nil, errors.ErrMfaTokenInvalidType.WithArgs(r.MfaToken.Type)
	}
	if r.WebAuthn.ExpectedOrigin == "" {
		return nil, errors.ErrWebAuthnRequest.WithArgs("trusted expected origin is empty")
	}
	if r.WebAuthn.Challenge == "" {
		return nil, errors.ErrWebAuthnChallengeNotFound
	}

	rpID, err := webAuthnRegistrationRPID(r.WebAuthn.ExpectedOrigin)
	if err != nil {
		return nil, err
	}
	registration, err := unpackWebAuthnRegistration(r.WebAuthn.Register)
	if err != nil {
		return nil, err
	}
	if registration.ClientData == nil {
		return nil, errors.ErrWebAuthnRequest.WithArgs("registration client data is nil")
	}
	if registration.ClientData.Type != "webauthn.create" {
		return nil, errors.ErrWebAuthnRequest.WithArgs("client data type is not webauthn.create")
	}
	if registration.ClientData.CrossOrigin {
		return nil, errors.ErrWebAuthnRequest.WithArgs("client data cross origin true is not supported")
	}
	if registration.ClientData.Challenge != r.WebAuthn.Challenge {
		return nil, errors.ErrWebAuthnRequest.WithArgs("client data challenge mismatch")
	}
	if registration.ClientData.Origin != r.WebAuthn.ExpectedOrigin {
		return nil, errors.ErrWebAuthnRequest.WithArgs("client data origin mismatch")
	}
	if registration.AttestationObject == nil || registration.AttestationObject.AuthData == nil {
		return nil, errors.ErrWebAuthnRegisterAuthDataNotFound
	}

	authData := registration.AttestationObject.AuthData
	rpIDHash := sha256.Sum256([]byte(rpID))
	if authData.RelyingPartyID != hex.EncodeToString(rpIDHash[:]) {
		return nil, errors.ErrWebAuthnRequest.WithArgs("registration rpIdHash mismatch")
	}
	if !authData.Flags["UP"] {
		return nil, errors.ErrWebAuthnRequest.WithArgs("registration User Present bit is not set")
	}
	if !authData.Flags["AT"] {
		return nil, errors.ErrWebAuthnRequest.WithArgs("registration Attested Credential Data bit is not set")
	}
	if authData.CredentialData != nil && authData.CredentialData.CredentialID != "" &&
		!equivalentWebAuthnCredentialIDs(registration.ID, authData.CredentialData.CredentialID) {
		return nil, errors.ErrWebAuthnRequest.WithArgs("registration credential id mismatch")
	}
	if err := validateWebAuthnRegistrationPublicKeyTypes(authData.CredentialData); err != nil {
		return nil, err
	}

	return NewMfaToken(r)
}

func webAuthnRegistrationRPID(expectedOrigin string) (string, error) {
	u, err := url.Parse(expectedOrigin)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.ErrWebAuthnRequest.WithArgs("trusted expected origin is invalid")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", errors.ErrWebAuthnRequest.WithArgs("trusted expected origin is invalid")
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", errors.ErrWebAuthnRequest.WithArgs("trusted expected origin is invalid")
	}
	return hostname, nil
}

func unpackWebAuthnRegistration(encoded string) (*WebAuthnRegisterRequest, error) {
	if encoded == "" {
		return nil, errors.ErrWebAuthnRegisterNotFound
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs(err)
	}
	registration := new(WebAuthnRegisterRequest)
	if err := json.Unmarshal(data, registration); err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs(err)
	}
	return registration, nil
}

func equivalentWebAuthnCredentialIDs(a, b string) bool {
	if a == b {
		return true
	}
	aBytes, aOK := decodeWebAuthnCredentialID(a)
	bBytes, bOK := decodeWebAuthnCredentialID(b)
	if !aOK || !bOK {
		return false
	}
	if len(aBytes) == len(bBytes) {
		return bytes.Equal(aBytes, bBytes)
	}
	// The legacy portal parser starts the credential at byte 55 but uses the
	// credential length as its slice end instead of 55+length. For credentials
	// longer than 55 bytes, this produces exactly the first length-55 bytes.
	legacyLength := len(aBytes) - 55
	return legacyLength > 0 && len(bBytes) == legacyLength && bytes.Equal(aBytes[:legacyLength], bBytes)
}

func decodeWebAuthnCredentialID(s string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if data, err := encoding.DecodeString(s); err == nil {
			return data, true
		}
	}
	return nil, false
}

func validateWebAuthnRegistrationPublicKeyTypes(credential *CredentialData) error {
	if credential == nil || credential.PublicKey == nil {
		return nil
	}
	for _, name := range []string{"key_type", "algorithm", "curve_type"} {
		if value, exists := credential.PublicKey[name]; exists {
			number, ok := value.(float64)
			if !ok || math.Trunc(number) != number {
				return errors.ErrWebAuthnRequest.WithArgs("registration public key parameter " + name + " has an invalid type")
			}
		}
	}
	for _, name := range []string{"curve_x", "curve_y", "exponent", "modulus"} {
		if value, exists := credential.PublicKey[name]; exists {
			if _, ok := value.(string); !ok {
				return errors.ErrWebAuthnRequest.WithArgs("registration public key parameter " + name + " has an invalid type")
			}
		}
	}
	return nil
}
