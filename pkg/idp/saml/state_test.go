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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStateManagerBrowserCallbackExpiryAndReplay(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	sm := newStateManager()
	sm.now = func() time.Time { return now }

	state, err := sm.add("browser-a", "https://portal.example/saml/upstream", "request-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, state, session, callback string
	}{
		{"missing state", "", "browser-a", "https://portal.example/saml/upstream"},
		{"wrong state", "wrong", "browser-a", "https://portal.example/saml/upstream"},
		{"missing browser", state, "", "https://portal.example/saml/upstream"},
		{"wrong browser", state, "browser-b", "https://portal.example/saml/upstream"},
		{"wrong callback", state, "browser-a", "https://other.example/saml/upstream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := sm.consume(tc.state, tc.session, tc.callback); ok {
				t.Fatal("unexpected state admission")
			}
		})
	}
	requestID, ok := sm.consume(state, "browser-a", "https://portal.example/saml/upstream")
	if !ok || requestID != "request-a" {
		t.Fatalf("valid binding rejected: requestID=%q ok=%v", requestID, ok)
	}
	if _, ok := sm.consume(state, "browser-a", "https://portal.example/saml/upstream"); ok {
		t.Fatal("replayed binding admitted")
	}

	expiredState, err := sm.add("browser-a", "https://portal.example/saml/upstream", "request-b")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(samlLoginLifetime)
	if _, ok := sm.consume(expiredState, "browser-a", "https://portal.example/saml/upstream"); ok {
		t.Fatal("expired binding admitted")
	}
}

func TestStateManagerSingleUseConcurrent(t *testing.T) {
	sm := newStateManager()
	state, err := sm.add("browser-a", "https://portal.example/saml/upstream", "request-a")
	if err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, ok := sm.consume(state, "browser-a", "https://portal.example/saml/upstream"); ok {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted %d callbacks, want 1", got)
	}
}

func TestStateManagerCapacityReclaimsExpired(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	sm := newStateManager()
	sm.maxStates = 1
	sm.now = func() time.Time { return now }
	if _, err := sm.add("browser-a", "https://portal.example/saml/upstream", "request-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.add("browser-b", "https://portal.example/saml/upstream", "request-b"); err == nil {
		t.Fatal("capacity was not enforced")
	}
	now = now.Add(samlLoginLifetime)
	if _, err := sm.add("browser-b", "https://portal.example/saml/upstream", "request-b"); err != nil {
		t.Fatalf("expired entry did not release capacity: %v", err)
	}
}
