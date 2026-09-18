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
	"crypto/subtle"
	"fmt"
	"sync"
	"time"
)

const defaultMaxStates = 10000

const oauthLoginLifetime = 5 * time.Minute

type loginBinding struct {
	sessionID     string
	callback      string
	nonceRequired bool
	claimed       bool
}

type stateManager struct {
	mux       sync.Mutex
	maxStates int
	nonces    map[string]string
	states    map[string]time.Time
	codes     map[string]string
	status    map[string]interface{}
	verifiers map[string]string
	bindings  map[string]loginBinding
}

func newStateManager() *stateManager {
	return &stateManager{
		maxStates: defaultMaxStates,
		nonces:    make(map[string]string),
		states:    make(map[string]time.Time),
		codes:     make(map[string]string),
		status:    make(map[string]interface{}),
		verifiers: make(map[string]string),
		bindings:  make(map[string]loginBinding),
	}
}

func (sm *stateManager) add(state, nonce string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if len(sm.states) >= sm.maxStates {
		return fmt.Errorf("OAuth state manager at capacity (%d)", sm.maxStates)
	}
	sm.nonces[state] = nonce
	sm.states[state] = time.Now()
	return nil
}

// addLogin publishes the nonce, verifier and browser binding together before
// the authorization redirect is returned. SessionID is supplied by the
// embedding application from its protected per-browser cookie, never a query.
func (sm *stateManager) addLogin(state, nonce, verifier, sessionID, callback string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if sessionID == "" || callback == "" {
		return fmt.Errorf("OAuth browser binding is missing")
	}
	if len(sm.states) >= sm.maxStates {
		return fmt.Errorf("OAuth state manager at capacity (%d)", sm.maxStates)
	}
	sm.states[state] = time.Now()
	sm.nonces[state] = nonce
	sm.verifiers[state] = verifier
	sm.bindings[state] = loginBinding{sessionID: sessionID, callback: callback, nonceRequired: nonce != ""}
	return nil
}

// beginCallback admits only one response from the initiating browser, at the
// initiating callback, within the transaction lifetime. Mismatched browsers
// cannot consume a legitimate pending transaction. Nonce and verifier stay
// available until the admitted request finishes and calls del.
func (sm *stateManager) beginCallback(state, sessionID, callback string) bool {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	binding, exists := sm.bindings[state]
	created, active := sm.states[state]
	if !exists || !active || binding.claimed || sessionID == "" || binding.callback != callback || time.Since(created) >= oauthLoginLifetime || subtle.ConstantTimeCompare([]byte(binding.sessionID), []byte(sessionID)) != 1 {
		return false
	}
	binding.claimed = true
	sm.bindings[state] = binding
	return true
}

func (sm *stateManager) del(state string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	delete(sm.nonces, state)
	delete(sm.states, state)
	delete(sm.codes, state)
	delete(sm.status, state)
	delete(sm.verifiers, state)
	delete(sm.bindings, state)
}

func (sm *stateManager) addVerifier(state, verifier string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.verifiers[state] = verifier
}

func (sm *stateManager) getVerifier(state string) (string, bool) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	v, exists := sm.verifiers[state]
	return v, exists
}

func (sm *stateManager) exists(state string) bool {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if _, exists := sm.states[state]; exists {
		return true
	}
	return false
}

func (sm *stateManager) validateNonce(state, nonce string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	v, exists := sm.nonces[state]
	if !exists {
		return fmt.Errorf("no nonce found for %s", state)
	}
	if subtle.ConstantTimeCompare([]byte(v), []byte(nonce)) != 1 {
		return fmt.Errorf("nonce mismatch for state %s", state)
	}
	return nil
}

// requiresNonce returns the policy captured when the login transaction was
// created. Legacy state entries created outside the browser login flow retain
// the historical required-nonce behavior.
func (sm *stateManager) requiresNonce(state string) (bool, error) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if binding, exists := sm.bindings[state]; exists {
		return binding.nonceRequired, nil
	}
	if _, exists := sm.states[state]; exists {
		return true, nil
	}
	return false, fmt.Errorf("no nonce policy found for %s", state)
}

func (sm *stateManager) addCode(state, code string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.codes[state] = code
}

func manageStateManager(sm *stateManager, stop <-chan struct{}) {
	intervals := time.NewTicker(time.Minute * time.Duration(2))
	defer intervals.Stop()
	for {
		select {
		case <-stop:
			return
		case <-intervals.C:
		}
		now := time.Now()
		sm.mux.Lock()
		for state, ts := range sm.states {
			deleteState := false
			if _, exists := sm.status[state]; !exists {
				if now.Sub(ts).Minutes() > 5 {
					deleteState = true
				}
			} else {
				if now.Sub(ts).Hours() > 12 {
					deleteState = true
				}
			}
			if deleteState {
				delete(sm.nonces, state)
				delete(sm.states, state)
				delete(sm.codes, state)
				delete(sm.status, state)
				delete(sm.verifiers, state)
				delete(sm.bindings, state)
			}
		}
		sm.mux.Unlock()
	}
}
