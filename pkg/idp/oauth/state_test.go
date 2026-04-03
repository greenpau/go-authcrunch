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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestManageStateManagerExpiry(t *testing.T) {
	testcases := []struct {
		name        string
		age         time.Duration
		hasStatus   bool
		shouldExist bool
	}{
		{
			name:        "state younger than 5 minutes is kept",
			age:         2 * time.Minute,
			hasStatus:   false,
			shouldExist: true,
		},
		{
			name:        "state older than 5 minutes is deleted",
			age:         6 * time.Minute,
			hasStatus:   false,
			shouldExist: false,
		},
		{
			name:        "state with status younger than 12 hours is kept",
			age:         6 * time.Minute,
			hasStatus:   true,
			shouldExist: true,
		},
		{
			name:        "state with status older than 12 hours is deleted",
			age:         13 * time.Hour,
			hasStatus:   true,
			shouldExist: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sm := newStateManager()
			state := "test-state"
			sm.states[state] = time.Now().Add(-tc.age)
			sm.nonces[state] = "test-nonce"
			sm.codes[state] = "test-code"
			if tc.hasStatus {
				sm.status[state] = "active"
			}

			// Inline the cleanup logic from manageStateManager because the
			// goroutine blocks on a ticker and cannot be called directly.
			now := time.Now()
			sm.mux.Lock()
			for s, ts := range sm.states {
				deleteState := false
				if _, exists := sm.status[s]; !exists {
					if now.Sub(ts).Minutes() > 5 {
						deleteState = true
					}
				} else {
					if now.Sub(ts).Hours() > 12 {
						deleteState = true
					}
				}
				if deleteState {
					delete(sm.nonces, s)
					delete(sm.states, s)
					delete(sm.codes, s)
					delete(sm.status, s)
				}
			}
			sm.mux.Unlock()

			if sm.exists(state) != tc.shouldExist {
				t.Errorf("state exists = %v, want %v", sm.exists(state), tc.shouldExist)
			}
		})
	}
}

func TestValidateNonce(t *testing.T) {
	testcases := []struct {
		name      string
		nonce     string
		input     string
		shouldErr bool
		err       error
	}{
		{
			name:  "valid nonce matches",
			nonce: "abc123",
			input: "abc123",
		},
		{
			name:      "invalid nonce rejected with same length",
			nonce:     "abc123",
			input:     "xyz789",
			shouldErr: true,
			err:       fmt.Errorf("nonce mismatch for state test-state"),
		},
		{
			name:      "missing state rejected",
			nonce:     "",
			input:     "any",
			shouldErr: true,
			err:       fmt.Errorf("no nonce found for test-state"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sm := newStateManager()
			state := "test-state"
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			if tc.nonce != "" {
				if err := sm.add(state, tc.nonce); err != nil {
					t.Fatalf("unexpected error from add: %v", err)
				}
			}

			err := sm.validateNonce(state, tc.input)
			if tests.EvalErrWithLog(t, err, "validateNonce", tc.shouldErr, tc.err, msgs) {
				return
			}

			// Verify nonce values are not leaked in error messages.
			if tc.shouldErr && tc.nonce != "" {
				if strings.Contains(err.Error(), tc.nonce) {
					t.Error("error message should not contain expected nonce value")
				}
				if strings.Contains(err.Error(), tc.input) {
					t.Error("error message should not contain received nonce value")
				}
			}
		})
	}
}

func TestStateManagerDel(t *testing.T) {
	sm := newStateManager()
	state := "test-state"
	if err := sm.add(state, "test-nonce"); err != nil {
		t.Fatalf("unexpected error from add: %v", err)
	}
	sm.addCode(state, "test-code")

	if !sm.exists(state) {
		t.Fatal("state should exist after add")
	}

	sm.del(state)

	if sm.exists(state) {
		t.Error("state should not exist after del")
	}
	sm.mux.Lock()
	if _, ok := sm.nonces[state]; ok {
		t.Error("nonce should be deleted")
	}
	if _, ok := sm.codes[state]; ok {
		t.Error("code should be deleted")
	}
	sm.mux.Unlock()
}

func TestStateManagerCapacity(t *testing.T) {
	testcases := []struct {
		name      string
		maxStates int
		fillCount int
		shouldErr bool
		err       error
	}{
		{
			name:      "add below capacity succeeds",
			maxStates: 5,
			fillCount: 4,
		},
		{
			name:      "add at capacity rejected",
			maxStates: 5,
			fillCount: 5,
			shouldErr: true,
			err:       fmt.Errorf("OAuth state manager at capacity (5)"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sm := newStateManager()
			sm.maxStates = tc.maxStates
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}

			for i := 0; i < tc.fillCount; i++ {
				if err := sm.add(fmt.Sprintf("state-%d", i), fmt.Sprintf("nonce-%d", i)); err != nil {
					t.Fatalf("unexpected error filling state %d: %v", i, err)
				}
			}

			err := sm.add("one-more", "one-more-nonce")
			if tests.EvalErrWithLog(t, err, "add", tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestStateManagerDefaultCapacity(t *testing.T) {
	sm := newStateManager()
	if sm.maxStates != defaultMaxStates {
		t.Fatalf("expected default maxStates %d, got %d", defaultMaxStates, sm.maxStates)
	}
}

func TestStateManagerCapacityAfterDel(t *testing.T) {
	sm := newStateManager()
	sm.maxStates = 2

	if err := sm.add("state-0", "nonce-0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := sm.add("state-1", "nonce-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := sm.add("state-2", "nonce-2"); err == nil {
		t.Fatal("expected error at capacity, got nil")
	}

	sm.del("state-0")

	if err := sm.add("state-2", "nonce-2"); err != nil {
		t.Fatalf("expected add to succeed after del, got: %v", err)
	}
}

func TestStateManagerVerifier(t *testing.T) {
	sm := newStateManager()
	state := "test-state"

	if _, ok := sm.getVerifier(state); ok {
		t.Fatal("expected no verifier for unknown state")
	}

	sm.addVerifier(state, "test-verifier")
	v, ok := sm.getVerifier(state)
	if !ok {
		t.Fatal("expected verifier to exist")
	}
	if v != "test-verifier" {
		t.Fatalf("expected verifier %q, got %q", "test-verifier", v)
	}
}

func TestStateManagerVerifierCleanup(t *testing.T) {
	sm := newStateManager()
	state := "test-state"
	if err := sm.add(state, "test-nonce"); err != nil {
		t.Fatalf("unexpected error from add: %v", err)
	}
	sm.addVerifier(state, "test-verifier")

	sm.del(state)

	if _, ok := sm.getVerifier(state); ok {
		t.Error("verifier should be deleted after del")
	}
}
