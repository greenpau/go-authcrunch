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

package authn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

var webAuthnChallengePattern = regexp.MustCompile(`challenge: "([^"]+)"`)

func webAuthnE2ERegistration(t *testing.T, rpID string) (requests.WebAuthn, *ecdsa.PrivateKey, string) {
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
	registration := identity.WebAuthnRegisterRequest{
		ID: "portal-origin-credential", Type: "public-key", Transports: []string{"internal"},
		AttestationObject: &identity.AttestationObject{AuthData: &identity.AuthData{
			RelyingPartyID: fmt.Sprintf("%x", rpIDHash), Flags: map[string]bool{"UP": true},
			CredentialData: &identity.CredentialData{PublicKey: map[string]any{
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
	return requests.WebAuthn{Register: base64.StdEncoding.EncodeToString(data), Challenge: "fixture-registration-challenge"}, key, registration.ID
}

func webAuthnE2EAssertion(t *testing.T, key *ecdsa.PrivateKey, credentialID, rpID, challenge, origin string) string {
	t.Helper()
	clientData, err := json.Marshal(identity.ClientData{Type: "webauthn.get", Challenge: challenge, Origin: origin})
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
	request := identity.WebAuthnAuthenticateRequest{
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

func TestE2EWebAuthnAssertionOriginBoundToTLSPortal(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, false, false, false, "")
	portalURL, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if portalURL.Port() == "" || portalURL.Port() == "443" {
		t.Fatal("TLS fixture did not exercise a non-default port")
	}
	registration, key, credentialID := webAuthnE2ERegistration(t, portalURL.Hostname())
	if err := store.Request(operator.AddMfaToken, &requests.Request{
		User:     requests.User{Username: "alice", Email: "alice@example.test"},
		MfaToken: requests.MfaToken{Type: "u2f", Comment: "portal origin key"}, WebAuthn: registration,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OverwriteUserAuthChallengeRules("alice", "alice@example.test", []string{"password u2f"}); err != nil {
		t.Fatal(err)
	}

	headers := http.Header{"Origin": {f.server.URL}}
	start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, headers)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	sandbox := start.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, headers), http.StatusSeeOther)
	challengePage := f.request(t, http.MethodGet, sandbox, nil, headers)
	oidcE2EStatus(t, challengePage, http.StatusOK)
	match := webAuthnChallengePattern.FindSubmatch(challengePage.body)
	if len(match) != 2 {
		t.Fatal("portal did not render the WebAuthn challenge")
	}
	challenge := string(match[1])
	parts := strings.Split(sandbox, "/sandbox/")
	if len(parts) != 2 {
		t.Fatal("missing sandbox location")
	}
	endpoint := parts[0] + "/sandbox/" + strings.SplitN(parts[1], "/", 2)[0] + "/mfa-u2f-auth"

	wrongOrigin := "https://evil." + portalURL.Hostname() + ":" + portalURL.Port()
	rejected := f.request(t, http.MethodPost, endpoint, url.Values{"webauthn_request": {
		webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), challenge, wrongOrigin),
	}}, headers)
	if rejected.status == http.StatusSeeOther || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("portal accepted an assertion signed for a different origin")
	}

	accepted := f.request(t, http.MethodPost, endpoint, url.Values{"webauthn_request": {
		webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), challenge, f.server.URL),
	}}, headers)
	oidcE2EStatus(t, accepted, http.StatusSeeOther)
	oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, headers), http.StatusSeeOther)
	loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice")
}
