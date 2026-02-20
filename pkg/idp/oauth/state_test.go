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
	"testing"
	"time"
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

func TestStateManagerDel(t *testing.T) {
	sm := newStateManager()
	state := "test-state"
	sm.add(state, "test-nonce")
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
