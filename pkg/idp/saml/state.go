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

package saml

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const (
	samlLoginLifetime = 5 * time.Minute
	defaultMaxStates  = 10000
)

type loginBinding struct {
	sessionID string
	callback  string
	requestID string
	expiresAt time.Time
}

type stateManager struct {
	mux       sync.Mutex
	bindings  map[string]loginBinding
	maxStates int
	now       func() time.Time
}

func newStateManager() *stateManager {
	return &stateManager{
		bindings:  make(map[string]loginBinding),
		maxStates: defaultMaxStates,
		now:       time.Now,
	}
}

func (sm *stateManager) add(sessionID, callback, requestID string) (string, error) {
	if sessionID == "" || callback == "" || requestID == "" {
		return "", fmt.Errorf("SAML browser binding is missing")
	}
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("failed generating SAML RelayState: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.deleteExpiredLocked()
	if len(sm.bindings) >= sm.maxStates {
		return "", fmt.Errorf("SAML state manager at capacity (%d)", sm.maxStates)
	}
	if _, exists := sm.bindings[state]; exists {
		return "", fmt.Errorf("generated duplicate SAML RelayState")
	}
	sm.bindings[state] = loginBinding{
		sessionID: sessionID,
		callback:  callback,
		requestID: requestID,
		expiresAt: sm.now().Add(samlLoginLifetime),
	}
	return state, nil
}

// consume admits a response only once, from the initiating browser, at the
// initiating callback. A mismatch does not consume another browser's state.
func (sm *stateManager) consume(state, sessionID, callback string) (string, bool) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	binding, exists := sm.bindings[state]
	if !exists || sessionID == "" || callback != binding.callback || !sm.now().Before(binding.expiresAt) || subtle.ConstantTimeCompare([]byte(sessionID), []byte(binding.sessionID)) != 1 {
		return "", false
	}
	delete(sm.bindings, state)
	return binding.requestID, true
}

func (sm *stateManager) del(state string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	delete(sm.bindings, state)
}

func (sm *stateManager) deleteExpiredLocked() {
	now := sm.now()
	for state, binding := range sm.bindings {
		if !now.Before(binding.expiresAt) {
			delete(sm.bindings, state)
		}
	}
}
