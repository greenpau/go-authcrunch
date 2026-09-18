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

package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func enrollmentTestBinding(scope string) webAuthnEnrollmentBinding {
	return webAuthnEnrollmentBinding{realm: "local", username: "alice", email: "alice@example.test", userID: "alice-id", backendVersion: "runtime", credentialVersion: 3, session: "session-id", origin: "https://auth.example.test:8443", scope: scope}
}

func enrollmentTestRequest(t *testing.T, challenge string) (*requests.Request, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("auth.example.test"))
	reg := identity.WebAuthnRegisterRequest{
		ID: "Y3JlZGVudGlhbA", Type: "public-key", Transports: []string{"internal"},
		ClientData: &identity.ClientData{Type: "webauthn.create", Origin: enrollmentTestBinding("profile").origin, Challenge: challenge},
		AttestationObject: &identity.AttestationObject{AuthData: &identity.AuthData{
			RelyingPartyID: hex.EncodeToString(rpHash[:]), Flags: map[string]bool{"UP": true, "AT": true},
			CredentialData: &identity.CredentialData{CredentialID: "Y3JlZGVudGlhbA", PublicKey: map[string]any{
				"key_type": 2, "algorithm": -7, "curve_type": 1,
				"curve_x": base64.StdEncoding.EncodeToString(public[1:33]), "curve_y": base64.StdEncoding.EncodeToString(public[33:]),
			}},
		}},
	}
	encoded, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	return &requests.Request{MfaToken: requests.MfaToken{Type: "u2f"}, WebAuthn: requests.WebAuthn{Challenge: challenge, Register: base64.StdEncoding.EncodeToString(encoded)}}, key
}

func enrollmentTestProof(t *testing.T, key *ecdsa.PrivateKey, challenge, origin string) string {
	t.Helper()
	client, err := json.Marshal(identity.ClientData{Type: "webauthn.get", Origin: origin, Challenge: challenge})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("auth.example.test"))
	authData := make([]byte, 37)
	copy(authData, rpHash[:])
	authData[32] = 1
	clientHash := sha256.Sum256(client)
	signedHash := sha256.Sum256(append(authData, clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(identity.WebAuthnAuthenticateRequest{
		ID: "Y3JlZGVudGlhbA", Type: "public-key", AuthDataEncoded: base64.StdEncoding.EncodeToString(authData),
		ClientDataEncoded: base64.StdEncoding.EncodeToString(client), SignatureEncoded: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func TestWebAuthnEnrollmentLifetimeAndCapacity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store := newWebAuthnEnrollmentStore(func() time.Time { return now }, 1)
	binding := enrollmentTestBinding("sandbox")
	first, err := store.issue(binding)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil || len(decoded) != 32 {
		t.Fatal("invalid challenge entropy or encoding")
	}
	other := binding
	other.session = "other"
	if _, err := store.issue(other); err == nil {
		t.Fatal("capacity limit bypassed")
	}
	second, err := store.issue(binding)
	if err != nil || first == second {
		t.Fatal("replacement did not create fresh challenge")
	}
	rr, _ := enrollmentTestRequest(t, first)
	if err := store.consume(binding, rr); err == nil {
		t.Fatal("replaced challenge accepted")
	}
	now = now.Add(webAuthnEnrollmentTTL)
	rr, _ = enrollmentTestRequest(t, second)
	if err := store.consume(binding, rr); err == nil {
		t.Fatal("expired challenge accepted")
	}
	if _, err := store.issue(other); err != nil {
		t.Fatalf("expiry did not free capacity: %v", err)
	}
	store.close()
	if len(store.entries) != 0 {
		t.Fatal("close retained outstanding ceremonies")
	}
	if _, err := store.issue(binding); err == nil {
		t.Fatal("closed store issued challenge")
	}
}

func TestWebAuthnEnrollmentBinding(t *testing.T) {
	changes := map[string]func(*webAuthnEnrollmentBinding){
		"backend version":    func(b *webAuthnEnrollmentBinding) { b.backendVersion = "reloaded" },
		"credential version": func(b *webAuthnEnrollmentBinding) { b.credentialVersion++ },
		"realm":              func(b *webAuthnEnrollmentBinding) { b.realm = "other" },
		"username":           func(b *webAuthnEnrollmentBinding) { b.username = "bob" },
		"email":              func(b *webAuthnEnrollmentBinding) { b.email = "bob@example.test" },
		"identity":           func(b *webAuthnEnrollmentBinding) { b.userID = "other-id" },
		"session":            func(b *webAuthnEnrollmentBinding) { b.session = "other-session" },
		"origin":             func(b *webAuthnEnrollmentBinding) { b.origin = "https://evil.example.test" },
		"scope":              func(b *webAuthnEnrollmentBinding) { b.scope = "profile" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			store := newWebAuthnEnrollmentStore(time.Now, 10)
			binding := enrollmentTestBinding("sandbox")
			challenge, err := store.issue(binding)
			if err != nil {
				t.Fatal(err)
			}
			rr, _ := enrollmentTestRequest(t, challenge)
			other := binding
			change(&other)
			if err := store.consume(other, rr); err == nil {
				t.Fatal("cross-binding enrollment accepted")
			}
			if err := store.consume(binding, rr); err != nil {
				t.Fatalf("foreign request consumed valid ceremony: %v", err)
			}
			if err := store.consume(binding, rr); err == nil {
				t.Fatal("replay accepted")
			}
		})
	}
}

func TestWebAuthnEnrollmentProfileProof(t *testing.T) {
	for _, outcome := range []string{"success", "wrong origin", "wrong challenge", "expired proof", "expired save", "closed"} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			store := newWebAuthnEnrollmentStore(func() time.Time { return now }, 10)
			binding := enrollmentTestBinding("profile")
			challenge, err := store.issue(binding)
			if err != nil {
				t.Fatal(err)
			}
			rr, key := enrollmentTestRequest(t, challenge)
			if err := store.consume(binding, rr); err == nil {
				t.Fatal("registration without proof accepted")
			}
			_, proofChallenge, err := store.prepare(binding, rr)
			if err != nil {
				t.Fatal(err)
			}
			if proofChallenge == challenge {
				t.Fatal("proof reused creation challenge")
			}
			if _, _, err := store.prepare(binding, rr); err == nil {
				t.Fatal("creation challenge reused")
			}
			if err := store.consume(binding, rr); err == nil {
				t.Fatal("registration without completed proof accepted")
			}
			origin := binding.origin
			if outcome == "wrong origin" {
				origin = "https://evil.example.test"
			}
			if outcome == "wrong challenge" {
				proofChallenge = challenge
			}
			if outcome == "expired proof" {
				now = now.Add(webAuthnEnrollmentTTL)
			}
			if outcome == "closed" {
				store.close()
			}
			rr.WebAuthn.Request = enrollmentTestProof(t, key, proofChallenge, origin)
			verifyErr := store.verify(binding, rr)
			if outcome != "success" && outcome != "expired save" {
				if verifyErr == nil {
					t.Fatal("invalid proof accepted")
				}
				if err := store.consume(binding, rr); err == nil {
					t.Fatal("failed proof allowed saving")
				}
				return
			}
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if err := store.verify(binding, rr); err == nil {
				t.Fatal("proof replay accepted")
			}
			swapped, _ := enrollmentTestRequest(t, challenge)
			if err := store.consume(binding, swapped); err == nil {
				t.Fatal("unproven replacement key accepted")
			}
			if outcome == "expired save" {
				now = now.Add(webAuthnEnrollmentTTL)
				if err := store.consume(binding, rr); err == nil {
					t.Fatal("expired verified enrollment saved")
				}
				return
			}
			if err := store.consume(binding, rr); err != nil {
				t.Fatal(err)
			}
			if err := store.consume(binding, rr); err == nil {
				t.Fatal("save replay accepted")
			}
		})
	}
}

func TestWebAuthnEnrollmentConcurrentConsumption(t *testing.T) {
	for _, scope := range []string{"sandbox", "profile"} {
		t.Run(scope, func(t *testing.T) {
			store := newWebAuthnEnrollmentStore(time.Now, 10)
			binding := enrollmentTestBinding(scope)
			challenge, err := store.issue(binding)
			if err != nil {
				t.Fatal(err)
			}
			rr, key := enrollmentTestRequest(t, challenge)
			if scope == "profile" {
				_, proof, err := store.prepare(binding, rr)
				if err != nil {
					t.Fatal(err)
				}
				rr.WebAuthn.Request = enrollmentTestProof(t, key, proof, binding.origin)
				var verified atomic.Int32
				var wg sync.WaitGroup
				for range 16 {
					wg.Go(func() {
						copyRequest := *rr
						if store.verify(binding, &copyRequest) == nil {
							verified.Add(1)
						}
					})
				}
				wg.Wait()
				if verified.Load() != 1 {
					t.Fatalf("proof accepted %d times", verified.Load())
				}
			}
			var accepted atomic.Int32
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					copyRequest := *rr
					if store.consume(binding, &copyRequest) == nil {
						accepted.Add(1)
					}
				})
			}
			wg.Wait()
			if accepted.Load() != 1 {
				t.Fatalf("enrollment accepted %d times", accepted.Load())
			}
		})
	}
}

func TestWebAuthnEnrollmentCanonicalAccount(t *testing.T) {
	r := httptest.NewRequest("POST", "https://auth.example.test:8443/auth/api/profile", nil)
	r.RequestURI = r.URL.RequestURI()
	rr := &requests.Request{User: requests.User{Username: "bob", Email: "alias@example.test"}}
	usr := &user.User{
		Claims:        &user.Claims{ID: "access-session", Subject: "bob", Email: "alias@example.test"},
		LoginUsername: "alice", LoginEmail: "alice@example.test",
		LoginEvidence: requests.AuthenticationEvidence{UserID: "alice-immutable-id", BackendVersion: "runtime", CredentialVersion: 7},
		Authenticator: user.Authenticator{Realm: "local", TempSessionID: "sandbox-session"},
	}
	binding, err := getWebAuthnEnrollmentBinding(r, rr, usr, "profile")
	if err != nil {
		t.Fatal(err)
	}
	if binding.username != "alice" || binding.email != "alice@example.test" || binding.userID != "alice-immutable-id" || binding.session != "access-session" || binding.origin != "https://auth.example.test:8443" {
		t.Fatal("enrollment was not bound to canonical login identity, session and origin")
	}
	if rr.User.Username != binding.username || rr.User.Email != binding.email {
		t.Fatal("backend target differs from ceremony owner")
	}
	sandbox, err := getWebAuthnEnrollmentBinding(r, rr, usr, "sandbox")
	if err != nil || sandbox.session != "sandbox-session" {
		t.Fatal("enrollment omitted sandbox session binding")
	}
	if _, err := getWebAuthnEnrollmentBinding(r, rr, nil, "profile"); err == nil {
		t.Fatal("nil user accepted")
	}
	usr.LoginEvidence = requests.AuthenticationEvidence{}
	if _, err := getWebAuthnEnrollmentBinding(r, rr, usr, "profile"); err == nil {
		t.Fatal("missing canonical evidence accepted")
	}
	usr.LoginEvidence = requests.AuthenticationEvidence{UserID: "alice-immutable-id", BackendVersion: "runtime"}
	usr.Claims.ID = ""
	if _, err := getWebAuthnEnrollmentBinding(r, rr, usr, "profile"); err == nil {
		t.Fatal("missing session accepted")
	}
}
