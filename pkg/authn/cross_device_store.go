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
	"errors"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

const (
	crossDeviceLifetime       = 5 * time.Minute
	crossDevicePollInterval   = 2 * time.Second
	crossDeviceCapacity       = 1024
	crossDeviceSourceCapacity = 8
)

var (
	errCrossDeviceDenied  = errors.New("cross-device request unavailable")
	errCrossDeviceLimited = errors.New("cross-device request limit reached")
	errCrossDevicePending = errors.New("cross-device authentication pending")
)

// All credentials are independent random capabilities. Only the activation code
// goes into the QR/link. The requester secret never leaves the requesting page.
// Records are volatile and bounded; pruning on admission needs no worker.
type crossDeviceStore struct {
	mu      sync.Mutex
	now     func() time.Time
	closed  bool
	entries map[[32]byte]*crossDeviceRequest
}

type crossDeviceRequest struct {
	code                              string
	secret                            [32]byte
	binding                           [32]byte
	origin, basePath, source, display string
	expires, nextPoll                 time.Time
	approved                          bool
	proof                             *crossDeviceProof
}

type crossDeviceProof struct {
	user             *user.User
	sessionID        string
	refreshSessionID string
	sessionToken     [32]byte
	expires          int64
	// Provider attributes captured before portal transforms, as JSON, so they
	// can be transformed for the requesting device without sharing maps.
	providerClaims []byte
	providerMethod string
}

func newCrossDeviceStore(now func() time.Time) *crossDeviceStore {
	return &crossDeviceStore{now: now, entries: make(map[[32]byte]*crossDeviceRequest)}
}

func crossDeviceHash(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func (s *crossDeviceStore) start(origin, basePath, source string) (*crossDeviceRequest, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, "", errCrossDeviceDenied
	}
	now := s.now()
	count := 0
	for k, entry := range s.entries {
		if !now.Before(entry.expires) {
			delete(s.entries, k)
			continue
		}
		if entry.source == source {
			count++
		}
	}
	if len(s.entries) >= crossDeviceCapacity || count >= crossDeviceSourceCapacity {
		return nil, "", errCrossDeviceLimited
	}
	secret := rand.Text()
	display := rand.Text()[:8]
	entry := &crossDeviceRequest{code: rand.Text(), secret: crossDeviceHash(secret), origin: origin, basePath: basePath, source: source, display: display[:4] + "-" + display[4:], expires: now.Add(crossDeviceLifetime)}
	s.entries[crossDeviceHash(entry.code)] = entry
	copy := *entry
	return &copy, secret, nil
}

// lookupLocked never accepts a capability at a different origin or portal mount.
func (s *crossDeviceStore) lookupLocked(code, origin, basePath string) (*crossDeviceRequest, error) {
	key := crossDeviceHash(code)
	entry := s.entries[key]
	if s.closed || entry == nil {
		return nil, errCrossDeviceDenied
	}
	if !s.now().Before(entry.expires) {
		delete(s.entries, key)
		return nil, errCrossDeviceDenied
	}
	if entry.origin != origin || entry.basePath != basePath {
		return nil, errCrossDeviceDenied
	}
	return entry, nil
}

func (s *crossDeviceStore) view(code, origin, basePath string) (*crossDeviceRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookupLocked(code, origin, basePath)
	if err != nil {
		return nil, err
	}
	copy := *entry
	copy.proof = nil
	return &copy, nil
}

func (s *crossDeviceStore) bind(code, binding, origin, basePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookupLocked(code, origin, basePath)
	if err != nil {
		return err
	}
	if entry.binding != ([32]byte{}) {
		return errCrossDeviceDenied
	}
	hash := crossDeviceHash(binding)
	for _, other := range s.entries {
		if other.binding == hash && s.now().Before(other.expires) {
			return errCrossDeviceDenied
		}
	}
	entry.binding = hash
	return nil
}

func (s *crossDeviceStore) boundLocked(binding, origin, basePath string) (*crossDeviceRequest, error) {
	if s.closed || binding == "" {
		return nil, errCrossDeviceDenied
	}
	hash := crossDeviceHash(binding)
	for _, entry := range s.entries {
		if entry.binding == hash {
			return s.lookupLocked(entry.code, origin, basePath)
		}
	}
	return nil, errCrossDeviceDenied
}

func (s *crossDeviceStore) complete(binding, origin, basePath string, proof *crossDeviceProof) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.boundLocked(binding, origin, basePath)
	if err != nil || entry.proof != nil || entry.approved || proof == nil || proof.user == nil || proof.user.Claims == nil || len(proof.providerClaims) > 65536 {
		return false
	}
	snapshot := *proof
	snapshot.user = proof.user.Clone()
	snapshot.providerClaims = append([]byte(nil), proof.providerClaims...)
	entry.proof = &snapshot
	return true
}

func (s *crossDeviceStore) confirmation(binding, origin, basePath string) (*crossDeviceRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.boundLocked(binding, origin, basePath)
	if err != nil {
		return nil, err
	}
	if entry.proof == nil || entry.approved || s.now().Unix() >= entry.proof.expires {
		return nil, errCrossDeviceDenied
	}
	copy := *entry
	proof := *entry.proof
	proof.user = proof.user.Clone()
	proof.providerClaims = append([]byte(nil), proof.providerClaims...)
	copy.proof = &proof
	return &copy, nil
}

func (s *crossDeviceStore) decide(binding, origin, basePath string, approve bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.boundLocked(binding, origin, basePath)
	if err != nil {
		return err
	}
	if entry.proof == nil || entry.approved || s.now().Unix() >= entry.proof.expires {
		return errCrossDeviceDenied
	}
	if !approve {
		delete(s.entries, crossDeviceHash(entry.code))
		return nil
	}
	entry.approved = true
	return nil
}

// poll atomically consumes approval before issuance. A failed/lost response
// requires a new interaction; retries cannot mint a second credential family.
func (s *crossDeviceStore) poll(code, secret, origin, basePath string, cancel bool) (*crossDeviceProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.lookupLocked(code, origin, basePath)
	if err != nil || entry.secret != crossDeviceHash(secret) {
		return nil, errCrossDeviceDenied
	}
	if cancel {
		delete(s.entries, crossDeviceHash(code))
		return nil, nil
	}
	now := s.now()
	if now.Before(entry.nextPoll) {
		return nil, errCrossDeviceLimited
	}
	entry.nextPoll = now.Add(crossDevicePollInterval)
	if !entry.approved {
		return nil, errCrossDevicePending
	}
	delete(s.entries, crossDeviceHash(code))
	if entry.proof == nil || now.Unix() >= entry.proof.expires {
		return nil, errCrossDeviceDenied
	}
	return entry.proof, nil
}

func (s *crossDeviceStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.entries)
}

// revoke removes outstanding transfers authorized by a session being logged out.
func (s *crossDeviceStore) revoke(sessionID, refreshSessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, entry := range s.entries {
		if entry.proof != nil && ((sessionID != "" && entry.proof.sessionID == sessionID) || (refreshSessionID != "" && entry.proof.refreshSessionID == refreshSessionID)) {
			delete(s.entries, code)
		}
	}
}
