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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

const webAuthnEnrollmentTTL = 5 * time.Minute
const webAuthnEnrollmentCapacity = 4096

var errWebAuthnEnrollment = errors.New("invalid or expired WebAuthn enrollment; restart registration")

type webAuthnEnrollmentBinding struct {
	realm, username, email, userID, session, origin, scope string
	backendVersion                                         string
	credentialVersion                                      uint64
}

type webAuthnEnrollmentPhase uint8

const (
	webAuthnEnrollmentCreated webAuthnEnrollmentPhase = iota
	webAuthnEnrollmentProofIssued
	webAuthnEnrollmentChecking
	webAuthnEnrollmentVerified
)

type webAuthnEnrollment struct {
	binding        webAuthnEnrollmentBinding
	expires        time.Time
	phase          webAuthnEnrollmentPhase
	registration   [sha256.Size]byte
	proofChallenge string
}

// Enrollment state is local to the portal runtime. A restart discards outstanding
// ceremonies. Only digests of registration payloads are retained, with a fixed
// lifetime, a capacity bound, and at most one ceremony per binding.
type webAuthnEnrollmentStore struct {
	mu       sync.Mutex
	entries  map[string]*webAuthnEnrollment
	now      func() time.Time
	capacity int
	closed   bool
}

func newWebAuthnEnrollmentStore(now func() time.Time, capacity int) *webAuthnEnrollmentStore {
	return &webAuthnEnrollmentStore{entries: make(map[string]*webAuthnEnrollment), now: now, capacity: capacity}
}

func (s *webAuthnEnrollmentStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.entries)
}

func newWebAuthnChallenge() string {
	b := make([]byte, 32)
	// crypto/rand.Read always fills b and fails irrecoverably on entropy failure.
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *webAuthnEnrollmentStore) issue(binding webAuthnEnrollmentBinding) (string, error) {
	if s == nil {
		return "", errWebAuthnEnrollment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", errWebAuthnEnrollment
	}
	now := s.now()
	for challenge, entry := range s.entries {
		if !now.Before(entry.expires) || entry.binding == binding {
			delete(s.entries, challenge)
		}
	}
	if len(s.entries) >= s.capacity {
		return "", errWebAuthnEnrollment
	}
	challenge := newWebAuthnChallenge()
	s.entries[challenge] = &webAuthnEnrollment{binding: binding, expires: now.Add(webAuthnEnrollmentTTL)}
	return challenge, nil
}

// lookup requires s.mu and never consumes another user's ceremony.
func (s *webAuthnEnrollmentStore) lookup(binding webAuthnEnrollmentBinding, challenge string) (*webAuthnEnrollment, error) {
	entry := s.entries[challenge]
	if s.closed || entry == nil || entry.binding != binding {
		return nil, errWebAuthnEnrollment
	}
	if !s.now().Before(entry.expires) {
		delete(s.entries, challenge)
		return nil, errWebAuthnEnrollment
	}
	return entry, nil
}

func (s *webAuthnEnrollmentStore) prepare(binding webAuthnEnrollmentBinding, rr *requests.Request) (*identity.MfaToken, string, error) {
	if s == nil {
		return nil, "", errWebAuthnEnrollment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookup(binding, rr.WebAuthn.Challenge)
	if err != nil || entry.phase != webAuthnEnrollmentCreated {
		return nil, "", errWebAuthnEnrollment
	}
	rr.WebAuthn.ExpectedOrigin = binding.origin
	token, err := identity.ValidateWebAuthnRegistration(rr)
	if err != nil {
		return nil, "", errWebAuthnEnrollment
	}
	entry.registration = sha256.Sum256([]byte(rr.WebAuthn.Register))
	entry.proofChallenge = newWebAuthnChallenge()
	entry.phase = webAuthnEnrollmentProofIssued
	return token, entry.proofChallenge, nil
}

func (s *webAuthnEnrollmentStore) verify(binding webAuthnEnrollmentBinding, rr *requests.Request) error {
	if s == nil {
		return errWebAuthnEnrollment
	}
	s.mu.Lock()
	entry, err := s.lookup(binding, rr.WebAuthn.Challenge)
	if err != nil || entry.phase != webAuthnEnrollmentProofIssued || entry.registration != sha256.Sum256([]byte(rr.WebAuthn.Register)) {
		s.mu.Unlock()
		return errWebAuthnEnrollment
	}
	entry.phase = webAuthnEnrollmentChecking
	challenge := entry.proofChallenge
	s.mu.Unlock()

	// The signed assertion proves possession of the registered key and binds
	// the proof to this server-issued challenge and origin. The registration
	// payload itself is pinned to the validated creation response.
	rr.WebAuthn.ExpectedOrigin = binding.origin
	token, verifyErr := identity.ValidateWebAuthnRegistration(rr)
	if verifyErr == nil {
		var assertion *identity.WebAuthnAuthenticateRequest
		assertion, verifyErr = token.WebAuthnRequest(rr.WebAuthn.Request)
		if verifyErr == nil && (assertion.ClientData.Challenge != challenge || assertion.ClientData.Origin != binding.origin) {
			verifyErr = errWebAuthnEnrollment
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.lookup(binding, rr.WebAuthn.Challenge)
	if err != nil || current != entry || current.phase != webAuthnEnrollmentChecking {
		return errWebAuthnEnrollment
	}
	if verifyErr != nil {
		delete(s.entries, rr.WebAuthn.Challenge)
		return errWebAuthnEnrollment
	}
	entry.phase = webAuthnEnrollmentVerified
	entry.proofChallenge = ""
	return nil
}

func (s *webAuthnEnrollmentStore) consume(binding webAuthnEnrollmentBinding, rr *requests.Request) error {
	if s == nil {
		return errWebAuthnEnrollment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookup(binding, rr.WebAuthn.Challenge)
	if err != nil {
		return errWebAuthnEnrollment
	}
	if binding.scope == "profile" {
		if entry.phase != webAuthnEnrollmentVerified || entry.registration != sha256.Sum256([]byte(rr.WebAuthn.Register)) {
			return errWebAuthnEnrollment
		}
	} else if binding.scope != "sandbox" || entry.phase != webAuthnEnrollmentCreated {
		return errWebAuthnEnrollment
	}
	rr.WebAuthn.ExpectedOrigin = binding.origin
	if _, err := identity.ValidateWebAuthnRegistration(rr); err != nil {
		return errWebAuthnEnrollment
	}
	// The identity store must compare this server-held evidence under its write
	// lock, so account replacement or a credential change cannot retarget an
	// already verified ceremony to a different security state.
	rr.Authentication = requests.AuthenticationEvidence{
		UserID: binding.userID, BackendVersion: binding.backendVersion,
		CredentialVersion: binding.credentialVersion,
	}
	// Consume before persistence: a failed write requires a fresh ceremony.
	delete(s.entries, rr.WebAuthn.Challenge)
	return nil
}

func getWebAuthnEnrollmentBinding(r *http.Request, rr *requests.Request, usr *user.User, scope string) (webAuthnEnrollmentBinding, error) {
	var binding webAuthnEnrollmentBinding
	if usr == nil || usr.Claims == nil {
		return binding, errWebAuthnEnrollment
	}
	origin, err := getWebAuthnExpectedOrigin(r)
	if err != nil {
		return binding, errWebAuthnEnrollment
	}
	// Select the same canonical account captured at login for all ceremony
	// stages, even when presentation claims have been transformed.
	if usr.LoginUsername != "" || usr.LoginEmail != "" {
		rr.User.Username, rr.User.Email = usr.LoginUsername, usr.LoginEmail
	}
	binding = webAuthnEnrollmentBinding{
		realm: usr.Authenticator.Realm, username: rr.User.Username, email: rr.User.Email,
		userID: usr.LoginEvidence.UserID, session: usr.Claims.ID, origin: origin, scope: scope,
		backendVersion: usr.LoginEvidence.BackendVersion, credentialVersion: usr.LoginEvidence.CredentialVersion,
	}
	if scope == "sandbox" {
		binding.session = usr.Authenticator.TempSessionID
	}
	if binding.realm == "" || binding.session == "" || binding.userID == "" || binding.backendVersion == "" || (binding.username == "" && binding.email == "") {
		return webAuthnEnrollmentBinding{}, errWebAuthnEnrollment
	}
	return binding, nil
}
