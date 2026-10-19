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

package oauth

import (
	"context"
	"sync"
	"time"
)

const defaultMaxStates = 10000
const oauthLoginLifetime = 5 * time.Minute

type loginKey struct{ namespace, state string }

// MemoryLoginStore is bounded, process-local OAuth transaction storage. Sharing
// this object coordinates consumers in one process only; it is not durable HA.
// The zero value is usable with the default capacity.
type MemoryLoginStore struct {
	mux       sync.Mutex
	maxStates int
	entries   map[loginKey]LoginTransaction
}

type stateManager = MemoryLoginStore

// NewMemoryLoginStore returns a private in-memory store with a 10,000-record cap.
func NewMemoryLoginStore() *MemoryLoginStore { return newStateManager() }
func newStateManager() *stateManager {
	return &stateManager{maxStates: defaultMaxStates, entries: make(map[loginKey]LoginTransaction)}
}

// Create atomically publishes a fresh, bounded transaction.
func (s *MemoryLoginStore) Create(ctx context.Context, namespace string, tx LoginTransaction) error {
	if s == nil || ctx == nil {
		return ErrLoginUnavailable
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	if tx.Validate(now) != nil || tx.Claim != "" {
		return ErrLoginInvalid
	}
	s.prune(now)
	key := loginKey{namespace, tx.State}
	if _, exists := s.entries[key]; exists {
		return ErrLoginInvalid
	}
	capacity := s.maxStates
	if capacity == 0 {
		capacity = defaultMaxStates
	}
	if len(s.entries) >= capacity {
		return ErrLoginCapacity
	}
	if s.entries == nil {
		s.entries = make(map[loginKey]LoginTransaction)
	}
	s.entries[key] = tx
	return nil
}

// Claim admits at most one matching callback.
func (s *MemoryLoginStore) Claim(ctx context.Context, namespace, state string, binding LoginBinding, claim string) (LoginTransaction, error) {
	if s == nil || ctx == nil {
		return LoginTransaction{}, ErrLoginUnavailable
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if err := ctx.Err(); err != nil {
		return LoginTransaction{}, err
	}
	key := loginKey{namespace, state}
	tx, exists := s.entries[key]
	if !exists || tx.Validate(time.Now()) != nil || tx.Claim != "" || !tx.Binding.Matches(binding) || !loginText(claim, 128) {
		return LoginTransaction{}, ErrLoginInvalid
	}
	tx.Claim = claim
	s.entries[key] = tx
	return tx, nil
}

// Get returns independent evidence, rejecting missing or expired records.
func (s *MemoryLoginStore) Get(ctx context.Context, namespace, state string) (LoginTransaction, error) {
	if s == nil || ctx == nil {
		return LoginTransaction{}, ErrLoginUnavailable
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if err := ctx.Err(); err != nil {
		return LoginTransaction{}, err
	}
	tx, exists := s.entries[loginKey{namespace, state}]
	if !exists || tx.Validate(time.Now()) != nil {
		return LoginTransaction{}, ErrLoginInvalid
	}
	return tx, nil
}

// Complete consumes only the admitted callback, rechecking expiry and claim.
func (s *MemoryLoginStore) Complete(ctx context.Context, namespace, state, claim string) error {
	if s == nil || ctx == nil {
		return ErrLoginUnavailable
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := loginKey{namespace, state}
	tx, exists := s.entries[key]
	if !exists || tx.Validate(time.Now()) != nil || claim == "" || tx.Claim != claim {
		return ErrLoginInvalid
	}
	delete(s.entries, key)
	return nil
}

// Cancel removes only the exact owner's pending or claimed transaction.
func (s *MemoryLoginStore) Cancel(ctx context.Context, namespace, state string, binding LoginBinding) (bool, error) {
	if s == nil || ctx == nil {
		return false, ErrLoginUnavailable
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	key := loginKey{namespace, state}
	tx, exists := s.entries[key]
	if !exists || tx.ExpiresAt <= time.Now().Unix() || !tx.Binding.Matches(binding) {
		return false, nil
	}
	delete(s.entries, key)
	return true, nil
}

func (s *MemoryLoginStore) prune(now time.Time) {
	for key, tx := range s.entries {
		if tx.ExpiresAt <= now.Unix() {
			delete(s.entries, key)
		}
	}
}

func manageStateManager(sm *stateManager, stop <-chan struct{}) {
	timer := time.NewTicker(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-timer.C:
			sm.mux.Lock()
			sm.prune(now)
			sm.mux.Unlock()
		}
	}
}
