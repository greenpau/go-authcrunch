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

package cache

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestPersistentSessionCache(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	var storage *state.Store
	open := func() *SessionCache {
		var err error
		storage, err = state.Open(&state.Config{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		record, err := storage.OpenRecord("sessions", "same")
		if err != nil {
			t.Fatal(err)
		}
		c := NewSessionCache()
		if err = c.ConfigurePersistentState(record); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := open()
	id := strings.Repeat("a", 32)
	u, err := user.NewUser(map[string]any{"sub": "alice", "jti": id, "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"authp/user"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Add(id, u); err != nil {
		t.Fatal(err)
	}
	_ = storage.Close()
	c = open()
	if got, err := c.Get(id); err != nil || got.Claims.Subject != "alice" {
		t.Fatal("session not restored")
	}
	if err = c.Delete(id); err != nil {
		t.Fatal(err)
	}
	_ = storage.Close()
	c = open()
	defer storage.Close()
	if _, err = c.Get(id); err == nil {
		t.Fatal("deleted session resurrected")
	}
	_ = storage.Close()
	if err = c.Add(id, u); err == nil {
		t.Fatal("failed persistence accepted session")
	}
	if _, err = c.Get(id); err == nil {
		t.Fatal("failed persistence served memory")
	}
}

func TestPersistentSessionCacheCapacityRollback(t *testing.T) {
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err := storage.OpenRecord("sessions", "same")
	if err != nil {
		t.Fatal(err)
	}
	c := NewSessionCache()
	if err = c.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	newSession := func(id, subject string, size int) *user.User {
		t.Helper()
		u, createErr := user.NewUser(map[string]any{"sub": subject, "jti": id, "exp": time.Now().Add(time.Hour).Unix(), "blob": strings.Repeat("x", size)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return u
	}
	firstID := strings.Repeat("c", 32)
	first := newSession(firstID, "first", 62<<20)
	if err = c.Add(firstID, first); err != nil {
		t.Fatal("preload near-capacity session", err)
	}
	baseline, err := record.Load()
	if err != nil {
		t.Fatal(err)
	}
	secondID := strings.Repeat("d", 32)
	if err = c.Add(secondID, newSession(secondID, "second", 3<<20)); !errors.Is(err, state.ErrCapacity) {
		t.Fatalf("growth returned %v, want capacity", err)
	}
	if _, exists := c.Entries[secondID]; exists {
		t.Fatal("capacity refusal published new session")
	}
	if err = c.Add(firstID, newSession(firstID, "replacement", 65<<20)); !errors.Is(err, state.ErrCapacity) {
		t.Fatalf("replacement returned %v, want capacity", err)
	}
	if c.Entries[firstID] == nil || c.Entries[firstID].user != first {
		t.Fatal("capacity refusal replaced prior live session")
	}
	if current, loadErr := record.Load(); loadErr != nil || !bytes.Equal(current, baseline) {
		t.Fatal("capacity refusal changed durable snapshot", loadErr)
	}
	if err = c.Err(); err != nil || c.Entries[firstID].user.Claims.Subject != "first" {
		t.Fatal("capacity refusal poisoned healthy cache", err)
	}
}

func TestPersistentSessionCacheFailsClosedOnSerializationError(t *testing.T) {
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err := storage.OpenRecord("sessions", "same")
	if err != nil {
		t.Fatal(err)
	}
	c := NewSessionCache()
	if err = c.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	u, err := user.NewUser(map[string]any{"sub": "alice", "jti": id, "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	u.Claims.Metadata = map[string]any{"unsupported": make(chan struct{})}
	if err = c.Add(id, u); err == nil {
		t.Fatal("unsupported session state was accepted")
	}
	if err = c.Err(); err == nil {
		t.Fatal("serialization failure did not poison cache")
	}
	if err = storage.Err(); err != nil {
		t.Fatal("component-local serialization failure unexpectedly poisoned store")
	}
}
