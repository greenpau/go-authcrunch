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

package identity

import (
	"encoding/base64"
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// WebAuthnAuthenticateRequest represents Webauthn Authentication request.
type WebAuthnAuthenticateRequest struct {
	ID                string      `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Type              string      `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	AuthData          *AuthData   `json:"auth_data,omitempty" xml:"auth_data,omitempty" yaml:"auth_data,omitempty"`
	AuthDataEncoded   string      `json:"auth_data_encoded,omitempty" xml:"auth_data_encoded,omitempty" yaml:"auth_data_encoded,omitempty"`
	ClientData        *ClientData `json:"client_data,omitempty" xml:"client_data,omitempty" yaml:"client_data,omitempty"`
	ClientDataEncoded string      `json:"client_data_encoded,omitempty" xml:"client_data_encoded,omitempty" yaml:"client_data_encoded,omitempty"`
	Signature         string      `json:"signature,omitempty" xml:"signature,omitempty" yaml:"signature,omitempty"`
	SignatureEncoded  string      `json:"signature_encoded,omitempty" xml:"signature_encoded,omitempty" yaml:"signature_encoded,omitempty"`
	clientDataBytes   []byte
	signatureBytes    []byte
	authDataBytes     []byte
}

// WebAuthnRegisterRequest is Webauthn Register request.
type WebAuthnRegisterRequest struct {
	ID                string             `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Type              string             `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Transports        []string           `json:"transports,omitempty" xml:"transports,omitempty" yaml:"transports,omitempty"`
	Success           bool               `json:"success,omitempty" xml:"success,omitempty" yaml:"success,omitempty"`
	AttestationObject *AttestationObject `json:"attestationObject,omitempty" xml:"attestationObject,omitempty" yaml:"attestationObject,omitempty"`
	ClientData        *ClientData        `json:"clientData,omitempty" xml:"clientData,omitempty" yaml:"clientData,omitempty"`
	Device            *Device            `json:"device,omitempty" xml:"device,omitempty" yaml:"device,omitempty"`
}

// AttestationObject is Webauthn AttestationObject.
type AttestationObject struct {
	AttestationStatement *AttestationStatement `json:"attStmt,omitempty" xml:"attStmt,omitempty" yaml:"attStmt,omitempty"`
	AuthData             *AuthData             `json:"authData,omitempty" xml:"authData,omitempty" yaml:"authData,omitempty"`
	Format               string                `json:"fmt,omitempty" xml:"fmt,omitempty" yaml:"fmt,omitempty"`
}

// AttestationStatement is AttestationStatement of the Webauthn AttestationObject.
type AttestationStatement struct {
	Algorithm int64  `json:"alg,omitempty" xml:"alg,omitempty" yaml:"alg,omitempty"`
	Signature string `json:"sig,omitempty" xml:"sig,omitempty" yaml:"sig,omitempty"`
	// The string in the first element of the slice contains the certificate associates
	// with the authenticaing device. The following commands allow the viewing of the
	// cerificate. The Subject contains the serial number associated with the device.
	// 1. `echo -n "base64 encoded value" | base64 -d > key.crt`
	// 2. `openssl x509 -in key.crt -inform der -text`
	Certificates []string `json:"x5c,omitempty" xml:"x5c,omitempty" yaml:"x5c,omitempty"`
}

// AuthData is AuthData of the Webauthn AttestationObject.
type AuthData struct {
	RelyingPartyID   string          `json:"rpIdHash,omitempty" xml:"rpIdHash,omitempty" yaml:"rpIdHash,omitempty"`
	Flags            map[string]bool `json:"flags,omitempty" xml:"flags,omitempty" yaml:"flags,omitempty"`
	SignatureCounter uint32          `json:"signatureCounter,omitempty" xml:"signatureCounter,omitempty" yaml:"signatureCounter,omitempty"`
	Extensions       interface{}     `json:"extensions,omitempty" xml:"extensions,omitempty" yaml:"extensions,omitempty"`
	CredentialData   *CredentialData `json:"credentialData,omitempty" xml:"credentialData,omitempty" yaml:"credentialData,omitempty"`
}

// CredentialData is attested credential data. It is a variable-length byte array
// added to the authenticator data when generating an attestation object for
// a given credential.
type CredentialData struct {
	// The AAGUID of the authenticator.
	AAGUID string `json:"aaguid,omitempty" xml:"aaguid,omitempty" yaml:"aaguid,omitempty"`
	// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
	CredentialID string `json:"credentialId,omitempty" xml:"credentialId,omitempty" yaml:"credentialId,omitempty"`
	// The credential public key encoded in COSE Key format
	PublicKey map[string]interface{} `json:"publicKey,omitempty" xml:"publicKey,omitempty" yaml:"publicKey,omitempty"`
}

// ClientData represents the contextual bindings of both the WebAuthn Relying Party and the client.
// It is a key-value mapping whose keys are strings. Values can be any type that has a valid
// encoding in JSON. Its structure is defined by the following Web IDL.
type ClientData struct {
	Challenge   string `json:"challenge,omitempty" xml:"challenge,omitempty" yaml:"challenge,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty" xml:"crossOrigin,omitempty" yaml:"crossOrigin,omitempty"`
	Origin      string `json:"origin,omitempty" xml:"origin,omitempty" yaml:"origin,omitempty"`
	Type        string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// Device is the hardware device on which the WebAuthn Client runs, for example a smartphone, a
// laptop computer or a desktop computer, and the operating system running on that hardware.
type Device struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Type string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

func unpackWebAuthnRequest(s string) (*WebAuthnAuthenticateRequest, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs(err)
	}
	r := &WebAuthnAuthenticateRequest{}
	if err := json.Unmarshal([]byte(decoded), r); err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs(err)
	}
	return r, nil
}
