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

package tokenrefresh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestRefreshCapacityReclamation(t *testing.T) {
	for _, reason := range []string{"logout", "replay", "identity denial", "idle expiry", "absolute expiry", "rotation exhaustion"} {
		t.Run(reason, func(t *testing.T) {
			h := newTestManager(t)
			h.store.capacity, h.store.maxRotations = 1, 1
			first := h.issue(t)
			next, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport)
			if err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "logout":
				if err := h.manager.Logout(t.Context(), next.RefreshToken, CookieTransport); err != nil {
					t.Fatal(err)
				}
			case "replay":
				if _, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
					t.Fatal("replay accepted")
				}
			case "identity denial":
				h.identity.err = ErrDenied
				if _, err := h.manager.Refresh(t.Context(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrDenied) {
					t.Fatal("identity denial ignored")
				}
				h.identity.err = nil
			case "idle expiry":
				h.clock.Store(next.RefreshExpiresAt)
			case "absolute expiry":
				h.clock.Store(next.AbsoluteExpiresAt)
			case "rotation exhaustion":
				if _, err := h.manager.Refresh(t.Context(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
					t.Fatal("rotation limit ignored")
				}
			}
			h.principal.AuthTime = h.clock.Load()
			fresh := h.issue(t)
			for _, credential := range []string{first.RefreshToken, next.RefreshToken} {
				if _, err := h.manager.Refresh(t.Context(), credential, CookieTransport); !errors.Is(err, ErrInvalid) {
					t.Fatal("terminal credential accepted")
				}
			}
			if len(h.store.families) != 1 || len(h.store.tokens) != 1 {
				t.Fatal("terminal evidence retained after admission")
			}
			if _, err := h.manager.Refresh(t.Context(), fresh.RefreshToken, CookieTransport); err != nil {
				t.Fatal("old credentials revoked new family", err)
			}
		})
	}
}

func TestRefreshCapacityRetainsLiveReplayEvidence(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity, h.store.maxRotations = 2, 3
	first, unrelated := h.issue(t), h.issue(t)
	current := first
	for range 3 {
		var err error
		current, err = h.manager.Refresh(t.Context(), current.RefreshToken, CookieTransport)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.manager.Issue(t.Context(), h.principal, CookieTransport); !errors.Is(err, ErrUnavailable) {
		t.Fatal("live family evicted")
	}
	if len(h.store.families) != 2 || len(h.store.tokens) != 5 {
		t.Fatal("live replay history lost")
	}
	if _, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("oldest spent credential accepted")
	}
	if _, err := h.manager.Refresh(t.Context(), current.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("oldest replay failed to revoke current descendant")
	}
	h.issue(t)
	if _, err := h.manager.Refresh(t.Context(), unrelated.RefreshToken, CookieTransport); err != nil {
		t.Fatal("unrelated family changed", err)
	}
}

func TestRefreshCapacityRepeatedReplacement(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity, h.store.maxRotations = 1, 2
	current := h.issue(t)
	for range 100 {
		old := current
		rotated, err := h.manager.Refresh(t.Context(), current.RefreshToken, CookieTransport)
		if err != nil {
			t.Fatal(err)
		}
		// Fresh authentication can retire the whole family using a spent browser
		// cookie. It cannot renew it, and must also retire its current descendant.
		current, err = h.manager.IssueReplacing(t.Context(), h.principal, CookieTransport, []string{old.RefreshToken, old.RefreshToken, "malformed"})
		if err != nil {
			t.Fatal(err)
		}
		if current.SessionID == old.SessionID {
			t.Fatal("replacement reused session")
		}
		for _, token := range []string{old.RefreshToken, rotated.RefreshToken} {
			if _, err := h.manager.GetSessionID(t.Context(), token, CookieTransport); !errors.Is(err, ErrInvalid) {
				t.Fatal("replaced family remains usable")
			}
		}
		if len(h.store.families) != 1 || len(h.store.tokens) != 1 {
			t.Fatal("replacement accumulated terminal state")
		}
	}
}

type legacyCapacityStore struct{ Store }

func TestRefreshReplacementFailuresPreserveFamily(t *testing.T) {
	for _, reason := range []string{"signing", "identity denial", "directory outage", "expired staging", "cancelled", "unsupported adapter", "unknown", "malformed", "wrong transport", "wrong portal", "wrong origin", "wrong mount"} {
		t.Run(reason, func(t *testing.T) {
			h := newTestManager(t)
			h.store.capacity = 1
			old := h.issue(t)
			previous := []string{old.RefreshToken}
			binding := h.manager.binding
			transport := CookieTransport
			ctx := t.Context()
			switch reason {
			case "signing":
				h.signer.sign = func(map[string]any) (string, error) { return "", errors.New("offline") }
			case "identity denial":
				h.identity.err = ErrDenied
			case "directory outage":
				h.identity.err = errors.New("offline")
			case "expired staging":
				h.signer.sign = func(map[string]any) (string, error) { h.clock.Add(60); return "staged", nil }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unsupported adapter":
				h.manager.store = legacyCapacityStore{h.store}
			case "unknown":
				token, _, err := newToken()
				if err != nil {
					t.Fatal(err)
				}
				previous = []string{token}
			case "malformed":
				previous = []string{"not a credential"}
			case "wrong transport":
				transport = BodyTransport
			case "wrong portal":
				h.manager.binding.Portal = "other"
			case "wrong origin":
				h.manager.binding.Origin = "https://other.test"
			case "wrong mount":
				h.manager.binding.BasePath = "/other"
			}
			result, err := h.manager.IssueReplacing(ctx, h.principal, transport, previous)
			if err == nil || result != nil {
				t.Fatal("failed replacement published credentials")
			}
			h.manager.binding, h.manager.store = binding, h.store
			h.signer.sign, h.identity.err = nil, nil
			if _, err := h.manager.Refresh(t.Context(), old.RefreshToken, CookieTransport); err != nil {
				t.Fatal("failed replacement consumed old family", err)
			}
		})
	}
}

func TestRefreshReplacementCommitValidation(t *testing.T) {
	for _, reason := range []string{"duplicate id", "duplicate digest", "revision", "idle expiry", "absolute expiry", "access expiry", "cancelled", "closed"} {
		t.Run(reason, func(t *testing.T) {
			h := newTestManager(t)
			h.store.capacity = 1
			first := h.issue(t)
			d, _ := digest(first.RefreshToken)
			b, _ := h.manager.transportBinding(CookieTransport)
			old, err := h.store.Lookup(t.Context(), d, b)
			if err != nil {
				t.Fatal(err)
			}
			next := cloneSession(old)
			next.ID = "new-id"
			_, next.Current, err = newToken()
			if err != nil {
				t.Fatal(err)
			}
			access := h.clock.Load() + 60
			ctx := t.Context()
			switch reason {
			case "duplicate id":
				next.ID = old.ID
			case "duplicate digest":
				next.Current = old.Current
			case "revision":
				next.Revision = 1
			case "idle expiry":
				next.IdleExpiresAt = h.clock.Load()
			case "absolute expiry":
				next.IdleExpiresAt = next.AbsoluteExpiresAt + 1
			case "access expiry":
				access = h.clock.Load()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				h.store.Close()
			}
			if err := h.store.CreateReplacing(ctx, next, access, [][32]byte{d}); err == nil {
				t.Fatal("invalid replacement committed")
			}
			if reason != "closed" {
				if _, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport); err != nil {
					t.Fatal("failed commit retired old family", err)
				}
			}
		})
	}
}

func TestRefreshCapacityConcurrentAdmission(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity = 1
	old := h.issue(t)
	if err := h.manager.Logout(t.Context(), old.RefreshToken, CookieTransport); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *Result, 16)
	for range 16 {
		wg.Go(func() {
			result, _ := h.manager.Issue(t.Context(), h.principal, CookieTransport)
			results <- result
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result != nil {
			successes++
		}
	}
	if successes != 1 || len(h.store.families) != 1 || len(h.store.tokens) != 1 {
		t.Fatal("concurrent admission exceeded capacity")
	}
}

func TestRefreshReplacementDuringRotation(t *testing.T) {
	for _, rotationFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(rotationFirst), func(t *testing.T) {
			h := newTestManager(t)
			h.store.capacity = 1
			first := h.issue(t)
			d, _ := digest(first.RefreshToken)
			b, _ := h.manager.transportBinding(CookieTransport)
			old, err := h.store.Lookup(t.Context(), d, b)
			if err != nil {
				t.Fatal(err)
			}
			_, next, err := newToken()
			if err != nil {
				t.Fatal(err)
			}
			// Both operations stage against the same old family. Exercise both atomic
			// commit orders; a late rotate must not resurrect the replaced snapshot.
			rotate := func() error { return h.store.Rotate(t.Context(), old, next, old.IdleExpiresAt, first.AccessExpiresAt) }
			if rotationFirst {
				if err := rotate(); err != nil {
					t.Fatal(err)
				}
			}
			fresh, err := h.manager.IssueReplacing(t.Context(), h.principal, CookieTransport, []string{first.RefreshToken})
			if err != nil {
				t.Fatal(err)
			}
			if !rotationFirst && !errors.Is(rotate(), ErrInvalid) {
				t.Fatal("late rotation resurrected retired family")
			}
			if _, err := h.store.Lookup(t.Context(), next, b); !errors.Is(err, ErrInvalid) {
				t.Fatal("old descendant survived replacement")
			}
			if _, err := h.manager.Refresh(t.Context(), fresh.RefreshToken, CookieTransport); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRefreshCapacityConcurrentStoreCommits(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity = 1
	first := h.issue(t)
	d, _ := digest(first.RefreshToken)
	b, _ := h.manager.transportBinding(CookieTransport)
	template, err := h.store.Lookup(t.Context(), d, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.manager.Logout(t.Context(), first.RefreshToken, CookieTransport); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := range 16 {
		staged := cloneSession(template)
		staged.ID = fmt.Sprint("new-", i)
		_, staged.Current, err = newToken()
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() { results <- h.store.Create(t.Context(), staged, first.AccessExpiresAt) })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if successes != 1 || len(h.store.families) != 1 || len(h.store.tokens) != 1 {
		t.Fatal("atomic store admissions exceeded limit")
	}
}

func TestRefreshCapacityConcurrentRotationReplacement(t *testing.T) {
	for range 20 {
		h := newTestManager(t)
		h.store.capacity = 1
		first := h.issue(t)
		d, _ := digest(first.RefreshToken)
		b, _ := h.manager.transportBinding(CookieTransport)
		old, err := h.store.Lookup(t.Context(), d, b)
		if err != nil {
			t.Fatal(err)
		}
		_, descendant, err := newToken()
		if err != nil {
			t.Fatal(err)
		}
		fresh := cloneSession(old)
		fresh.ID = "replacement"
		_, fresh.Current, err = newToken()
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			close(entered)
			done <- h.store.Rotate(t.Context(), old, descendant, old.IdleExpiresAt, first.AccessExpiresAt)
		}()
		<-entered
		if err := h.store.CreateReplacing(t.Context(), fresh, first.AccessExpiresAt, [][32]byte{d}); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil && !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := h.store.Lookup(t.Context(), descendant, b); !errors.Is(err, ErrInvalid) {
			t.Fatal("concurrent rotation survived replacement")
		}
		if got, err := h.store.Lookup(t.Context(), fresh.Current, b); err != nil || got.ID != fresh.ID {
			t.Fatal("replacement family lost")
		}
		if len(h.store.families) != 1 || len(h.store.tokens) != 1 {
			t.Fatal("concurrent commits exceeded limit")
		}
	}
}

func TestRefreshReplacementMultipleFamilies(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity = 3
	first, second, third := h.issue(t), h.issue(t), h.issue(t)
	fresh, err := h.manager.IssueReplacing(t.Context(), h.principal, CookieTransport, []string{first.RefreshToken, second.RefreshToken, first.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.store.families) != 2 || len(h.store.tokens) != 2 {
		t.Fatal("duplicate paths caused incorrect capacity accounting")
	}
	for _, token := range []string{first.RefreshToken, second.RefreshToken} {
		if _, err := h.manager.Refresh(t.Context(), token, CookieTransport); !errors.Is(err, ErrInvalid) {
			t.Fatal("presented old family survived")
		}
	}
	for _, token := range []string{fresh.RefreshToken, third.RefreshToken} {
		if _, err := h.manager.Refresh(t.Context(), token, CookieTransport); err != nil {
			t.Fatal("unreplaced family revoked", err)
		}
	}
}

func TestRefreshCapacityRenewedIdleDeadline(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity = 2
	first := h.issue(t)
	h.clock.Add(250)
	current, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Add(100) // Past the initial idle deadline, before its renewed deadline.
	h.issue(t)       // Opportunistic cleanup must retain the live family's old digest.
	if _, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("spent token accepted after initial idle deadline")
	}
	if _, err := h.manager.Refresh(t.Context(), current.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("cleanup lost live replay history")
	}
}
