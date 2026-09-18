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

package oauth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	stateBindingState    = "state-binding"
	stateBindingNonce    = "nonce-binding"
	stateBindingVerifier = "verifier-binding"
	stateBindingSession  = "browser-session"
	stateBindingCallback = "https://portal.example/oauth2/test/authorization-code-callback"
)

func addStateBinding(t *testing.T, sm *stateManager, state string) {
	t.Helper()
	if err := sm.addLogin(state, stateBindingNonce, stateBindingVerifier, stateBindingSession, stateBindingCallback); err != nil {
		t.Fatalf("addLogin() error = %v", err)
	}
}

func TestStateBindingValidCallback(t *testing.T) {
	sm := newStateManager()
	addStateBinding(t, sm, stateBindingState)

	if !sm.beginCallback(stateBindingState, stateBindingSession, stateBindingCallback) {
		t.Fatal("matching callback was rejected")
	}
	if nonceErr := sm.validateNonce(stateBindingState, stateBindingNonce); nonceErr != nil {
		t.Fatalf("claimed callback lost nonce: %v", nonceErr)
	}
	if verifier, exists := sm.getVerifier(stateBindingState); !exists || verifier != stateBindingVerifier {
		t.Fatalf("claimed callback verifier = %q, %t", verifier, exists)
	}
}

func TestStateBindingRejectsWrongOrMissingSession(t *testing.T) {
	for _, tc := range []struct{ name, sessionID string }{
		{name: "missing", sessionID: ""},
		{name: "wrong", sessionID: "different-browser"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := newStateManager()
			addStateBinding(t, sm, stateBindingState)

			if sm.beginCallback(stateBindingState, tc.sessionID, stateBindingCallback) {
				t.Fatal("mismatched browser session claimed callback")
			}
			if !sm.beginCallback(stateBindingState, stateBindingSession, stateBindingCallback) {
				t.Fatal("rejected browser session consumed callback")
			}
		})
	}
}

func TestStateBindingRejectsWrongCallback(t *testing.T) {
	sm := newStateManager()
	addStateBinding(t, sm, stateBindingState)

	if sm.beginCallback(stateBindingState, stateBindingSession, "https://portal.example/other/authorization-code-callback") {
		t.Fatal("wrong callback claimed state")
	}
	if !sm.beginCallback(stateBindingState, stateBindingSession, stateBindingCallback) {
		t.Fatal("wrong callback consumed state")
	}
}

func TestStateBindingRejectsExpiredCallbackBeforeMaintenance(t *testing.T) {
	sm := newStateManager()
	addStateBinding(t, sm, stateBindingState)
	sm.mux.Lock()
	sm.states[stateBindingState] = time.Now().Add(-oauthLoginLifetime - time.Second)
	sm.mux.Unlock()

	if sm.beginCallback(stateBindingState, stateBindingSession, stateBindingCallback) {
		t.Fatal("expired callback was accepted before maintenance cleanup")
	}
	if !sm.exists(stateBindingState) {
		t.Fatal("test did not exercise pre-maintenance state")
	}
}

func TestStateBindingCallbackClaimIsAtomic(t *testing.T) {
	sm := newStateManager()
	addStateBinding(t, sm, stateBindingState)

	const callbacks = 32
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	var accepted atomic.Int32
	ready.Add(callbacks)
	done.Add(callbacks)
	for range callbacks {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			if sm.beginCallback(stateBindingState, stateBindingSession, stateBindingCallback) {
				accepted.Add(1)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	if got := accepted.Load(); got != 1 {
		t.Fatalf("simultaneous callbacks accepted = %d, want 1", got)
	}
}

func TestStateBindingDeletionReleasesCapacity(t *testing.T) {
	sm := newStateManager()
	sm.maxStates = 1
	addStateBinding(t, sm, stateBindingState)
	if err := sm.addLogin("at-capacity", stateBindingNonce, stateBindingVerifier, stateBindingSession, stateBindingCallback); err == nil {
		t.Fatal("addLogin() succeeded at capacity")
	}
	if !sm.beginCallback(stateBindingState, stateBindingSession, stateBindingCallback) {
		t.Fatal("matching callback was rejected")
	}
	sm.del(stateBindingState)

	if err := sm.addLogin("replacement", stateBindingNonce, stateBindingVerifier, stateBindingSession, stateBindingCallback); err != nil {
		t.Fatalf("addLogin() after deletion error = %v", err)
	}
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if _, exists := sm.bindings[stateBindingState]; exists {
		t.Fatal("deletion retained browser binding")
	}
}

func TestStateBindingRequiresBrowserAndCallback(t *testing.T) {
	for _, tc := range []struct {
		name, sessionID, callback string
	}{
		{name: "missing browser", callback: stateBindingCallback},
		{name: "missing callback", sessionID: stateBindingSession},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := newStateManager()
			if err := sm.addLogin(stateBindingState, stateBindingNonce, stateBindingVerifier, tc.sessionID, tc.callback); err == nil {
				t.Fatal("addLogin() accepted incomplete browser binding")
			}
			if sm.exists(stateBindingState) {
				t.Fatal("rejected addLogin() published state")
			}
		})
	}
}
