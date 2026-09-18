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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newWebAuthnOriginTestUser(t *testing.T, rpID string) (*User, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	registration := WebAuthnRegisterRequest{
		ID: "origin-test-credential", Type: "public-key", Transports: []string{"internal"},
		AttestationObject: &AttestationObject{AuthData: &AuthData{
			RelyingPartyID: fmt.Sprintf("%x", rpIDHash), Flags: map[string]bool{"UP": true},
			CredentialData: &CredentialData{PublicKey: map[string]any{
				"key_type": 2, "algorithm": -7, "curve_type": 1,
				"curve_x": base64.StdEncoding.EncodeToString(public[1:33]),
				"curve_y": base64.StdEncoding.EncodeToString(public[33:65]),
			}},
		}},
	}
	data, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	token, err := NewMfaToken(&requests.Request{
		MfaToken: requests.MfaToken{Type: "u2f", Comment: "origin test"},
		WebAuthn: requests.WebAuthn{Register: base64.StdEncoding.EncodeToString(data), Challenge: "registration-challenge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &User{MfaTokens: []*MfaToken{token}}, key, registration.ID
}

func webAuthnOriginTestAssertion(t *testing.T, key *ecdsa.PrivateKey, credentialID, rpID, challenge, origin string) string {
	t.Helper()
	clientData, err := json.Marshal(ClientData{Type: "webauthn.get", Challenge: challenge, Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData, rpIDHash[:])
	authData[32] = 0x01
	clientDataHash := sha256.Sum256(clientData)
	signedData := append(append([]byte{}, authData...), clientDataHash[:]...)
	signedDataHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, key, signedDataHash[:])
	if err != nil {
		t.Fatal(err)
	}
	request := WebAuthnAuthenticateRequest{
		ID: credentialID, Type: "public-key",
		AuthDataEncoded:   base64.StdEncoding.EncodeToString(authData),
		ClientDataEncoded: base64.StdEncoding.EncodeToString(clientData),
		SignatureEncoded:  base64.StdEncoding.EncodeToString(signature),
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func TestVerifyWebAuthnRequestBindsSignedOrigin(t *testing.T) {
	const (
		rpID      = "login.example.test"
		challenge = "server-generated-challenge"
		origin    = "https://login.example.test:9443"
	)
	user, key, credentialID := newWebAuthnOriginTestUser(t, rpID)

	tests := []struct {
		name, signedOrigin, expectedOrigin, requestChallenge string
		wantErr                                              bool
	}{
		{name: "matching non-default port", signedOrigin: origin, expectedOrigin: origin, requestChallenge: challenge},
		{name: "different signed origin", signedOrigin: "https://evil.login.example.test:9443", expectedOrigin: origin, requestChallenge: challenge, wantErr: true},
		{name: "missing signed origin", expectedOrigin: origin, requestChallenge: challenge, wantErr: true},
		{name: "missing trusted expected origin", signedOrigin: origin, requestChallenge: challenge, wantErr: true},
		{name: "wrong challenge remains rejected", signedOrigin: origin, expectedOrigin: origin, requestChallenge: "wrong", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := &requests.Request{WebAuthn: requests.WebAuthn{
				Request:   webAuthnOriginTestAssertion(t, key, credentialID, rpID, challenge, tc.signedOrigin),
				Challenge: tc.requestChallenge, ExpectedOrigin: tc.expectedOrigin,
			}}
			err := user.VerifyWebAuthnRequest(request)
			if tc.wantErr && err == nil {
				t.Fatal("WebAuthn assertion unexpectedly accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("WebAuthn assertion rejected: %v", err)
			}
		})
	}
}
