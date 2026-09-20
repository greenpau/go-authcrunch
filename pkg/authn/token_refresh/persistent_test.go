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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

func capacitySession(id string, current byte, padding int) Session {
	return Session{
		ID: id,
		Principal: Principal{
			Backend: "local", Realm: "local", UserID: "immutable", Subject: "alice",
			Methods: []string{strings.Repeat("x", padding)},
		},
		Binding:           Binding{Portal: "portal", Origin: "https://auth.example.test", BasePath: "/auth", Transport: CookieTransport},
		Current:           [32]byte{current},
		IdleExpiresAt:     2000,
		AbsoluteExpiresAt: 3000,
	}
}

func prepareNearCapacityFamilies(t *testing.T, record *state.Record) (Session, Session, []byte) {
	t.Helper()
	const payloadLimit = 64 << 20
	padding := payloadLimit - 8192
	session := capacitySession("retained", 1, padding)
	other := capacitySession("other", 2, 0)
	prepare := func() ([]byte, error) {
		return record.PrepareEncode([]persistentFamily{
			{Session: other, Digests: [][32]byte{other.Current}},
			{Session: session, Digests: [][32]byte{session.Current}},
		})
	}
	prepared, err := prepare()
	if err != nil {
		t.Fatal(err)
	}
	padding += payloadLimit - len(prepared) - 1
	session.Principal.Methods[0] = strings.Repeat("x", padding)
	prepared, err = prepare()
	if err != nil {
		t.Fatal(err)
	}
	if payloadLimit-len(prepared) > 8 {
		t.Fatalf("capacity fixture left %d bytes unused", payloadLimit-len(prepared))
	}
	return session, other, prepared
}

func TestPersistentRefreshReplayAndRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	var storage *state.Store
	open := func() *testManager {
		h := newTestManager(t)
		var err error
		storage, err = state.Open(&state.Config{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		record, err := storage.OpenRecord("refresh", "same")
		if err != nil {
			t.Fatal(err)
		}
		if err = h.store.ConfigurePersistentState(record); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := open()
	first := h.issue(t)
	next, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	h = open()
	if id, err := h.manager.GetSessionID(t.Context(), next.RefreshToken, CookieTransport); err != nil || id != first.SessionID {
		t.Fatal("family lost on restart")
	}
	if _, err = h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("spent refresh restored")
	}
	_ = storage.Close()
	h = open()
	if _, err = h.manager.Refresh(t.Context(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("replay revocation not durable")
	}
	fresh := h.issue(t)
	if err = h.manager.Logout(t.Context(), fresh.RefreshToken, CookieTransport); err != nil {
		t.Fatal(err)
	}
	_ = storage.Close()
	h = open()
	if _, err = h.manager.Refresh(t.Context(), fresh.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("logout not durable")
	}
	live := h.issue(t)
	_ = storage.Close()
	if _, err = h.manager.Refresh(t.Context(), live.RefreshToken, CookieTransport); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable state permitted issuance")
	}
	h = open()
	defer storage.Close()
	h.clock.Add(3601)
	if _, err = h.manager.Refresh(t.Context(), live.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("absolute expiry extended")
	}
}

func TestE2EPersistentRefreshCapacityRollback(t *testing.T) {
	if directory := os.Getenv("AUTHCRUNCH_REFRESH_CAPACITY_CHILD"); directory != "" {
		storage, err := state.Open(&state.Config{Directory: directory})
		if err != nil {
			t.Fatal(err)
		}
		record, err := storage.OpenRecord("refresh", "capacity")
		if err != nil {
			t.Fatal(err)
		}
		retained, other, prepared := prepareNearCapacityFamilies(t, record)
		if err = record.Save(prepared); err != nil {
			t.Fatal(err)
		}
		store, err := NewMemoryStore(3, 2)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return time.Unix(1000, 0) }
		if err = store.ConfigurePersistentState(record); err != nil {
			t.Fatal(err)
		}
		current, err := store.Lookup(context.Background(), retained.Current, retained.Binding)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Rotate(context.Background(), current, [32]byte{3}, 2100, 1500); !errors.Is(err, state.ErrCapacity) {
			t.Fatalf("rotation capacity error: %v", err)
		}
		current, err = store.Lookup(context.Background(), retained.Current, retained.Binding)
		if err != nil || current.Current != retained.Current || current.Revision != 0 || current.IdleExpiresAt != retained.IdleExpiresAt || current.AbsoluteExpiresAt != retained.AbsoluteExpiresAt || len(store.families[retained.ID].digests) != 1 {
			t.Fatal("refused rotation changed retained family")
		}
		independent := capacitySession("independent", 4, 0)
		if err = store.Create(context.Background(), independent, 1500); !errors.Is(err, state.ErrCapacity) {
			t.Fatalf("creation capacity error: %v", err)
		}
		replacement := capacitySession("replacement", 5, len(retained.Principal.Methods[0])+4096)
		if err = store.CreateReplacing(context.Background(), replacement, 1500, [][32]byte{retained.Current, other.Current}); !errors.Is(err, state.ErrCapacity) {
			t.Fatalf("replacement capacity error: %v", err)
		}
		if _, err = store.Lookup(context.Background(), retained.Current, retained.Binding); err != nil {
			t.Fatalf("capacity refusal lost retained family: %v", err)
		}
		if _, err = store.Lookup(context.Background(), other.Current, other.Binding); err != nil {
			t.Fatalf("capacity refusal lost second replaced family: %v", err)
		}
		if err = storage.Err(); err != nil {
			t.Fatalf("capacity refusal poisoned shared storage: %v", err)
		}
		unrelated, err := storage.OpenRecord("unrelated", "binding")
		if err != nil {
			t.Fatal(err)
		}
		if err = unrelated.Encode(map[string]string{"healthy": "yes"}); err != nil {
			t.Fatalf("capacity refusal prevented unrelated commit: %v", err)
		}
		if err = store.Revoke(context.Background(), other.Current, other.Binding); err != nil {
			t.Fatalf("revocation at capacity failed: %v", err)
		}
		os.Exit(0)
	}

	directory := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestE2EPersistentRefreshCapacityRollback$")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_REFRESH_CAPACITY_CHILD="+directory)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capacity child failed: %v %s", err, output)
	}
	storage, err := state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err := storage.OpenRecord("refresh", "capacity")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewMemoryStore(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Unix(1000, 0) }
	if err = store.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	retained := capacitySession("retained", 1, 0)
	if _, err = store.Lookup(context.Background(), retained.Current, retained.Binding); err != nil {
		t.Fatal("retained family did not survive capacity refusal and process restart")
	}
	if _, err = store.Lookup(context.Background(), [32]byte{3}, retained.Binding); !errors.Is(err, ErrInvalid) {
		t.Fatal("refused rotation became current after restart")
	}
	other := capacitySession("other", 2, 0)
	if _, err = store.Lookup(context.Background(), other.Current, other.Binding); !errors.Is(err, ErrInvalid) {
		t.Fatal("revoked family survived process restart")
	}
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err = storage.OpenRecord("refresh", "capacity")
	if err != nil {
		t.Fatal(err)
	}
	store, err = NewMemoryStore(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Unix(1000, 0) }
	if err = store.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Lookup(context.Background(), other.Current, other.Binding); !errors.Is(err, ErrInvalid) {
		t.Fatal("revoked family survived second reopen")
	}
}
