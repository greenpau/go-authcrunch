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
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

func crossDeviceStoreFixture(t *testing.T) (*crossDeviceStore, *time.Time, *crossDeviceRequest, string, *crossDeviceProof) {
	t.Helper()
	now := time.Now()
	s := newCrossDeviceStore(func() time.Time { return now })
	e, secret, err := s.start("https://portal.test", "/auth/", "192.0.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := user.NewUser(map[string]any{"sub": "alice", "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	u.LoginMethods = []string{"pwd"}
	proof := &crossDeviceProof{user: u, expires: now.Add(time.Hour).Unix(), providerClaims: []byte(`{"sub":"alice"}`)}
	return s, &now, e, secret, proof
}

func TestCrossDeviceStoreLifecycle(t *testing.T) {
	s, now, e, secret, proof := crossDeviceStoreFixture(t)
	if e.code == secret || e.display == e.code {
		t.Fatal("capabilities not separated")
	}
	if _, err := s.poll(e.code, e.code, e.origin, e.basePath, false); !errors.Is(err, errCrossDeviceDenied) {
		t.Fatal("activation code redeemed")
	}
	for _, scope := range [][2]string{{"https://evil.test", e.basePath}, {e.origin, "/other/"}} {
		if _, err := s.view(e.code, scope[0], scope[1]); err == nil {
			t.Fatal("cross-scope lookup accepted")
		}
		if err := s.bind(e.code, "binding", scope[0], scope[1]); err == nil {
			t.Fatal("cross-scope bind accepted")
		}
	}
	if _, err := s.poll(e.code, secret, e.origin, e.basePath, false); !errors.Is(err, errCrossDevicePending) {
		t.Fatal("new request not pending")
	}
	if _, err := s.poll(e.code, secret, e.origin, e.basePath, false); !errors.Is(err, errCrossDeviceLimited) {
		t.Fatal("rapid polling allowed")
	}
	if err := s.bind(e.code, "binding", e.origin, e.basePath); err != nil {
		t.Fatal(err)
	}
	if err := s.bind(e.code, "different", e.origin, e.basePath); err == nil {
		t.Fatal("browser binding replaced")
	}
	if err := s.decide("binding", e.origin, e.basePath, true); err == nil {
		t.Fatal("approval before login")
	}
	if s.complete("wrong", e.origin, e.basePath, proof) {
		t.Fatal("wrong browser completed")
	}
	if !s.complete("binding", e.origin, e.basePath, proof) {
		t.Fatal("login did not complete")
	}
	proof.user.LoginMethods[0] = "forged"
	proof.providerClaims[0] = '!'
	if s.complete("binding", e.origin, e.basePath, proof) {
		t.Fatal("proof replaced")
	}
	view, err := s.confirmation("binding", e.origin, e.basePath)
	if err != nil || view.proof.user.LoginMethods[0] != "pwd" || view.proof.providerClaims[0] != '{' {
		t.Fatal("completion did not snapshot proof")
	}
	view.proof.user.LoginMethods[0] = "changed"
	if err := s.decide("binding", e.origin, e.basePath, true); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(crossDevicePollInterval)
	result, err := s.poll(e.code, secret, e.origin, e.basePath, false)
	if err != nil || result.user.LoginMethods[0] != "pwd" {
		t.Fatal("approved proof unavailable or shared")
	}
	if _, err := s.poll(e.code, secret, e.origin, e.basePath, false); err == nil {
		t.Fatal("replayed proof")
	}
}

func TestCrossDeviceStoreExpiryCancellationAndShutdown(t *testing.T) {
	for _, state := range []string{"expired", "cancelled", "denied", "closed", "proof expired"} {
		t.Run(state, func(t *testing.T) {
			s, now, e, secret, proof := crossDeviceStoreFixture(t)
			if err := s.bind(e.code, "binding", e.origin, e.basePath); err != nil {
				t.Fatal(err)
			}
			if !s.complete("binding", e.origin, e.basePath, proof) {
				t.Fatal("complete")
			}
			switch state {
			case "expired":
				*now = now.Add(crossDeviceLifetime)
			case "cancelled":
				if _, err := s.poll(e.code, secret, e.origin, e.basePath, true); err != nil {
					t.Fatal(err)
				}
			case "denied":
				if err := s.decide("binding", e.origin, e.basePath, false); err != nil {
					t.Fatal(err)
				}
			case "closed":
				s.close()
				s.close()
			case "proof expired":
				s.entries[crossDeviceHash(e.code)].proof.expires = now.Unix()
			}
			if _, err := s.confirmation("binding", e.origin, e.basePath); err == nil {
				t.Fatal("dead request confirmed")
			}
			if err := s.decide("binding", e.origin, e.basePath, true); err == nil {
				t.Fatal("dead request approved")
			}
			if state == "closed" {
				if _, _, err := s.start(e.origin, e.basePath, "new", ""); err == nil {
					t.Fatal("closed store admitted request")
				}
			}
		})
	}
}

func TestCrossDeviceStoreCapacity(t *testing.T) {
	s, now, e, _, _ := crossDeviceStoreFixture(t)
	for i := 1; i < crossDeviceSourceCapacity; i++ {
		if _, _, err := s.start(e.origin, e.basePath, e.source, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.start(e.origin, e.basePath, e.source, ""); !errors.Is(err, errCrossDeviceLimited) {
		t.Fatal("source capacity bypassed")
	}
	for i := crossDeviceSourceCapacity; i < crossDeviceCapacity; i++ {
		if _, _, err := s.start(e.origin, e.basePath, fmt.Sprint(i), ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.start(e.origin, e.basePath, "new", ""); !errors.Is(err, errCrossDeviceLimited) {
		t.Fatal("global capacity bypassed")
	}
	*now = now.Add(crossDeviceLifetime)
	if _, _, err := s.start(e.origin, e.basePath, e.source, ""); err != nil {
		t.Fatal("expired requests retained capacity")
	}
}

func TestCrossDeviceStoreConcurrentRedemption(t *testing.T) {
	s, _, e, secret, proof := crossDeviceStoreFixture(t)
	if err := s.bind(e.code, "binding", e.origin, e.basePath); err != nil {
		t.Fatal(err)
	}
	if !s.complete("binding", e.origin, e.basePath, proof) {
		t.Fatal("complete")
	}
	if err := s.decide("binding", e.origin, e.basePath, true); err != nil {
		t.Fatal(err)
	}
	var issued atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := s.poll(e.code, secret, e.origin, e.basePath, false); err == nil {
				issued.Add(1)
			}
		})
	}
	wg.Wait()
	if issued.Load() != 1 {
		t.Fatal("approval was not consumed exactly once")
	}
}

func TestCrossDeviceStoreBindingIsolationAndLogout(t *testing.T) {
	s, _, first, _, proof := crossDeviceStoreFixture(t)
	second, secret, err := s.start(first.origin, first.basePath, "other", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.bind(first.code, "binding", first.origin, first.basePath); err != nil {
		t.Fatal(err)
	}
	if err := s.bind(second.code, "binding", second.origin, second.basePath); err == nil {
		t.Fatal("one browser capability bound to two requests")
	}
	if err := s.bind(second.code, "second", second.origin, second.basePath); err != nil {
		t.Fatal(err)
	}
	proof.sessionID = "original"
	proof.refreshSessionID = "family"
	if !s.complete("binding", first.origin, first.basePath, proof) || !s.complete("second", second.origin, second.basePath, proof) {
		t.Fatal("completion failed")
	}
	s.revoke("unrelated", "unrelated")
	if err := s.decide("second", second.origin, second.basePath, true); err != nil {
		t.Fatal("unrelated logout revoked request")
	}
	// A rotated access JWT has another jti but the same refresh family.
	s.revoke("rotated", "family")
	if _, err := s.poll(second.code, secret, second.origin, second.basePath, false); !errors.Is(err, errCrossDeviceDenied) {
		t.Fatal("logged-out family redeemed")
	}
}

// Approver identity evidence must never replace the requester's navigation.
func TestCrossDeviceStoreRequesterDestinations(t *testing.T) {
	s, _, _, _, proof := crossDeviceStoreFixture(t)
	destinations := []string{"https://app.test/first", "https://app.test/second", ""}
	entries := make([]*crossDeviceRequest, len(destinations))
	secrets := make([]string, len(destinations))
	for i, destination := range destinations {
		var err error
		entries[i], secrets[i], err = s.start("https://portal.test", "/auth/", fmt.Sprint(i), destination)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, e := range slices.Backward(entries) {
		binding := fmt.Sprint(i)
		if err := s.bind(e.code, binding, e.origin, e.basePath); err != nil {
			t.Fatal(err)
		}
		proof.returnURL = "https://app.test/approver"
		if !s.complete(binding, e.origin, e.basePath, proof) {
			t.Fatal("complete")
		}
		if err := s.decide(binding, e.origin, e.basePath, true); err != nil {
			t.Fatal(err)
		}
		result, err := s.poll(e.code, secrets[i], e.origin, e.basePath, false)
		if err != nil {
			t.Fatal(err)
		}
		if result.returnURL != destinations[i] {
			t.Fatalf("destination = %q, want %q", result.returnURL, destinations[i])
		}
		if _, err := s.poll(e.code, secrets[i], e.origin, e.basePath, false); err == nil {
			t.Fatal("replayed transfer")
		}
	}
}
