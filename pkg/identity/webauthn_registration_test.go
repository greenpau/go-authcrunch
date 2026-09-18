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
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const (
	webAuthnRegistrationOrigin    = "https://login.example.test:9443"
	webAuthnRegistrationChallenge = "server-generated-registration-challenge"
)

func validWebAuthnRegistration(t *testing.T) (*requests.Request, *WebAuthnRegisterRequest) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte{0xfb, 0xff, 0x01, 0x02, 0x03}
	rpIDHash := sha256.Sum256([]byte("login.example.test"))
	registration := &WebAuthnRegisterRequest{
		ID:         base64.RawURLEncoding.EncodeToString(credentialID),
		Type:       "public-key",
		Transports: []string{"internal"},
		Success:    true,
		AttestationObject: &AttestationObject{AuthData: &AuthData{
			RelyingPartyID: hex.EncodeToString(rpIDHash[:]),
			Flags:          map[string]bool{"UP": true, "AT": true},
			CredentialData: &CredentialData{
				CredentialID: base64.StdEncoding.EncodeToString(credentialID),
				PublicKey: map[string]any{
					"key_type": 2, "algorithm": -7, "curve_type": 1,
					"curve_x": base64.StdEncoding.EncodeToString(publicKey[1:33]),
					"curve_y": base64.StdEncoding.EncodeToString(publicKey[33:65]),
				},
			},
		}},
		ClientData: &ClientData{
			Type: "webauthn.create", Challenge: webAuthnRegistrationChallenge,
			Origin: webAuthnRegistrationOrigin,
		},
	}
	r := &requests.Request{
		MfaToken: requests.MfaToken{Type: "u2f", Comment: "registration test"},
		WebAuthn: requests.WebAuthn{
			Challenge: webAuthnRegistrationChallenge, ExpectedOrigin: webAuthnRegistrationOrigin,
		},
	}
	setWebAuthnRegistration(t, r, registration)
	return r, registration
}

func setWebAuthnRegistration(t *testing.T, r *requests.Request, registration *WebAuthnRegisterRequest) {
	t.Helper()
	data, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	r.WebAuthn.Register = base64.StdEncoding.EncodeToString(data)
}

func TestValidateWebAuthnRegistration(t *testing.T) {
	r, registration := validWebAuthnRegistration(t)
	token, err := ValidateWebAuthnRegistration(r)
	if err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	if token.Type != "u2f" {
		t.Fatalf("token type: got %q, want u2f", token.Type)
	}
	if got, want := token.Parameters["u2f_id"], registration.ID; got != want {
		t.Fatalf("credential ID: got %q, want %q", got, want)
	}
	if got, want := token.Parameters["rp_id_hash"], registration.AttestationObject.AuthData.RelyingPartyID; got != want {
		t.Fatalf("RP ID hash: got %q, want %q", got, want)
	}

	t.Run("legacy empty nested credential ID", func(t *testing.T) {
		r, registration := validWebAuthnRegistration(t)
		registration.AttestationObject.AuthData.CredentialData.CredentialID = ""
		setWebAuthnRegistration(t, r, registration)
		if _, err := ValidateWebAuthnRegistration(r); err != nil {
			t.Fatalf("legacy registration rejected: %v", err)
		}
	})

	t.Run("legacy truncated nested credential ID", func(t *testing.T) {
		r, registration := validWebAuthnRegistration(t)
		credentialID := make([]byte, 64)
		for i := range credentialID {
			credentialID[i] = byte(i)
		}
		registration.ID = base64.RawURLEncoding.EncodeToString(credentialID)
		registration.AttestationObject.AuthData.CredentialData.CredentialID = base64.StdEncoding.EncodeToString(credentialID[:9])
		setWebAuthnRegistration(t, r, registration)
		if _, err := ValidateWebAuthnRegistration(r); err != nil {
			t.Fatalf("legacy registration rejected: %v", err)
		}
	})
}

func TestValidateWebAuthnRegistrationRejectsUnboundData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*requests.Request, *WebAuthnRegisterRequest)
	}{
		{name: "missing expected origin", mutate: func(r *requests.Request, _ *WebAuthnRegisterRequest) { r.WebAuthn.ExpectedOrigin = "" }},
		{name: "wrong MFA token type", mutate: func(r *requests.Request, _ *WebAuthnRegisterRequest) {
			r.MfaToken = requests.MfaToken{Type: "totp", Secret: "attacker-secret", Period: 30, Digits: 6, SkipVerification: true}
		}},
		{name: "invalid expected origin", mutate: func(r *requests.Request, _ *WebAuthnRegisterRequest) {
			r.WebAuthn.ExpectedOrigin = "https://login.example.test/path"
		}},
		{name: "missing challenge", mutate: func(r *requests.Request, _ *WebAuthnRegisterRequest) { r.WebAuthn.Challenge = "" }},
		{name: "missing client data", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) { registration.ClientData = nil }},
		{name: "wrong client data type", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.ClientData.Type = "webauthn.get"
		}},
		{name: "cross origin", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.ClientData.CrossOrigin = true
		}},
		{name: "challenge mismatch", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.ClientData.Challenge = "attacker-challenge"
		}},
		{name: "origin mismatch", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.ClientData.Origin = "https://evil.example.test"
		}},
		{name: "RP ID hash mismatch", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			hash := sha256.Sum256([]byte("evil.example.test"))
			registration.AttestationObject.AuthData.RelyingPartyID = hex.EncodeToString(hash[:])
		}},
		{name: "user not present", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.AttestationObject.AuthData.Flags["UP"] = false
		}},
		{name: "attested data absent", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.AttestationObject.AuthData.Flags["AT"] = false
		}},
		{name: "credential ID mismatch", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.AttestationObject.AuthData.CredentialData.CredentialID = base64.StdEncoding.EncodeToString([]byte{0xfa, 0xff, 0x01, 0x02, 0x03})
		}},
		{name: "inexact legacy credential ID prefix", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			credentialID := make([]byte, 64)
			for i := range credentialID {
				credentialID[i] = byte(i)
			}
			registration.ID = base64.RawURLEncoding.EncodeToString(credentialID)
			registration.AttestationObject.AuthData.CredentialData.CredentialID = base64.StdEncoding.EncodeToString(credentialID[:8])
		}},
		{name: "invalid public key value type", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.AttestationObject.AuthData.CredentialData.PublicKey["curve_x"] = true
		}},
		{name: "fractional public key number", mutate: func(_ *requests.Request, registration *WebAuthnRegisterRequest) {
			registration.AttestationObject.AuthData.CredentialData.PublicKey["key_type"] = 2.5
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, registration := validWebAuthnRegistration(t)
			tc.mutate(r, registration)
			setWebAuthnRegistration(t, r, registration)
			if _, err := ValidateWebAuthnRegistration(r); err == nil {
				t.Fatal("unbound WebAuthn registration accepted")
			}
		})
	}
}

func TestValidateWebAuthnRegistrationRejectsMalformedInput(t *testing.T) {
	if _, err := ValidateWebAuthnRegistration(nil); err == nil {
		t.Fatal("nil request accepted")
	}
	r, _ := validWebAuthnRegistration(t)
	r.WebAuthn.Register = "not base64"
	if _, err := ValidateWebAuthnRegistration(r); err == nil {
		t.Fatal("malformed registration accepted")
	}
}
