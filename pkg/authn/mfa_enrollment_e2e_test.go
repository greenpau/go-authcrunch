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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// This synthetic registration deliberately uses only public client inputs.
// No existing MFA credential is needed to construct the enrollment payload.
func enrollmentU2FRequest(t *testing.T) requests.WebAuthn {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("example.test"))
	registration := identity.WebAuthnRegisterRequest{
		ID: "synthetic-enrollment-credential", Type: "public-key", Transports: []string{"usb"},
		AttestationObject: &identity.AttestationObject{AuthData: &identity.AuthData{
			RelyingPartyID: fmt.Sprintf("%x", rp), Flags: map[string]bool{"UP": true},
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
	return requests.WebAuthn{Register: base64.StdEncoding.EncodeToString(data), Challenge: "synthetic-enrollment-challenge"}
}

func TestE2EMFAEnrollmentRequiresExistingFactor(t *testing.T) {
	for _, existing := range []string{"totp", "u2f"} {
		for _, features := range []string{"access", "refresh", "oidc"} {
			t.Run(existing+"/"+features, func(t *testing.T) {
				f, store, _ := newLoginIdentityE2E(t, features == "refresh", features == "oidc", existing == "totp", "")
				registration := enrollmentU2FRequest(t)
				if existing == "u2f" {
					if err := store.Request(operator.AddMfaToken, &requests.Request{
						User:     requests.User{Username: "alice", Email: "alice@example.test"},
						MfaToken: requests.MfaToken{Type: "u2f", Comment: "existing factor"}, WebAuthn: registration,
					}); err != nil {
						t.Fatal(err)
					}
				}
				origin := http.Header{"Origin": {f.server.URL}}
				start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
				oidcE2EStatus(t, start, http.StatusSeeOther)
				sandbox := start.header.Get("Location")
				oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
				var action string
				var form url.Values
				if existing == "totp" {
					action = "mfa-u2f-register"
					form = url.Values{"webauthn_register": {registration.Register}, "webauthn_challenge": {registration.Challenge}}
				} else {
					action = "mfa-app-register"
					form = url.Values{"type": {"totp"}, "secret": {loginIdentityTOTPSecret}, "period": {"30"}, "digits": {"6"}, "passcode": {loginIdentityTOTP()}, "comment": {"unauthorized alternate factor"}}
				}
				parts := strings.Split(sandbox, "/sandbox/")
				if len(parts) != 2 {
					t.Fatal("missing sandbox location")
				}
				endpoint := parts[0] + "/sandbox/" + strings.SplitN(parts[1], "/", 2)[0] + "/" + action
				response := f.request(t, http.MethodPost, endpoint, form, origin)
				if response.status != http.StatusForbidden {
					t.Errorf("alternate enrollment returned HTTP %d, want forbidden", response.status)
				}
				lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
				if err := store.Request(operator.GetMfaTokens, lookup); err != nil {
					t.Fatal(err)
				}
				bundle := lookup.Response.Payload.(*identity.MfaTokenBundle)
				if bundle.Size() != 1 || bundle.Get()[0].Type != existing {
					t.Fatal("password-only attacker persisted an alternate MFA factor")
				}
				if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" || loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") != "" {
					t.Fatal("unverified MFA enrollment issued credentials")
				}
				if existing == "totp" {
					// Denying enrollment preserves the legitimate existing-factor path.
					oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {loginIdentityTOTP()}}, origin), http.StatusSeeOther)
					oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
					loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice")
				}
			})
		}
	}
}

func TestE2EMFAHonorsRequiredFactor(t *testing.T) {
	for _, required := range []string{"u2f", "mfa"} {
		t.Run(required, func(t *testing.T) {
			f, store, _ := newLoginIdentityE2E(t, false, false, true, "")
			if err := store.Request(operator.AddMfaToken, &requests.Request{
				User:     requests.User{Username: "alice", Email: "alice@example.test"},
				MfaToken: requests.MfaToken{Type: "u2f", Comment: "hardware factor"}, WebAuthn: enrollmentU2FRequest(t),
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.OverwriteUserAuthChallengeRules("alice", "alice@example.test", []string{"password " + required}); err != nil {
				t.Fatal(err)
			}
			origin := http.Header{"Origin": {f.server.URL}}
			start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
			oidcE2EStatus(t, start, http.StatusSeeOther)
			sandbox := start.header.Get("Location")
			oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
			parts := strings.Split(sandbox, "/sandbox/")
			endpoint := parts[0] + "/sandbox/" + strings.SplitN(parts[1], "/", 2)[0] + "/mfa-app-auth"
			response := f.request(t, http.MethodPost, endpoint, url.Values{"passcode": {loginIdentityTOTP()}}, origin)
			if required == "u2f" {
				oidcE2EStatus(t, response, http.StatusForbidden)
				if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
					t.Fatal("TOTP satisfied a required hardware factor")
				}
				return
			}
			oidcE2EStatus(t, response, http.StatusSeeOther)
			oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
			loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice")
		})
	}
}
