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

package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	storage "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
	storageparser "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite/parser"
)

func storeConfig(t *testing.T) *storage.Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := storageparser.NewSQLiteOAuthLoginStoreConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "login.db")}), "capacity 2"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func transaction(state string) oauth.LoginTransaction {
	now := time.Now()
	return oauth.LoginTransaction{State: state, Nonce: "nonce", NonceRequired: true, Verifier: "verifier", ReturnURL: "/welcome",
		Binding: oauth.LoginBinding{Browser: sha256.Sum256([]byte("browser")), Callback: "https://portal.example/callback"}, CreatedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()}
}
func TestSQLiteLoginTransactions(t *testing.T) {
	cfg := storeConfig(t)
	a, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	tx := transaction("state")
	if err := a.Create(t.Context(), "namespace", tx); err != nil {
		t.Fatal(err)
	}
	if err := b.Create(t.Context(), "namespace", tx); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("overwrote transaction")
	}
	if _, err := b.Get(t.Context(), "other", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("cross-namespace read")
	}
	wrong := tx.Binding
	wrong.Callback += "/other"
	if _, err := b.Claim(t.Context(), "namespace", tx.State, wrong, "claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("wrong binding accepted")
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		client := a
		if i%2 == 1 {
			client = b
		}
		wg.Go(func() {
			if _, err := client.Claim(t.Context(), "namespace", tx.State, tx.Binding, "claim"); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, oauth.ErrLoginInvalid) {
				t.Errorf("claim: %v", err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners: %d", winners.Load())
	}
	got, err := b.Get(t.Context(), "namespace", tx.State)
	if err != nil || got.Nonce != tx.Nonce || got.Verifier != tx.Verifier || got.ReturnURL != tx.ReturnURL || got.Claim != "claim" {
		t.Fatal("lost evidence")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Claim(t.Context(), "namespace", tx.State, tx.Binding, "again"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("reopen resurrected claim")
	}
	if err := c.Complete(t.Context(), "namespace", tx.State, "wrong"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("wrong completion")
	}
	if err := c.Complete(t.Context(), "namespace", tx.State, "claim"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(t.Context(), "namespace", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("completion not shared")
	}
	for _, state := range []string{"a", "b"} {
		if err := b.Create(t.Context(), "namespace", transaction(state)); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Create(t.Context(), "namespace", transaction("c")); !errors.Is(err, oauth.ErrLoginCapacity) {
		t.Fatal("capacity not enforced")
	}
	if ok, err := c.Cancel(t.Context(), "namespace", "a", wrong); err != nil || ok {
		t.Fatal("mismatch canceled")
	}
	if _, err := c.Claim(t.Context(), "namespace", "a", tx.Binding, "canceled"); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.Cancel(t.Context(), "namespace", "a", tx.Binding); err != nil || !ok {
		t.Fatal("cancellation failed")
	}
	if err := c.Complete(t.Context(), "namespace", "a", "canceled"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("canceled callback completed")
	}
	if err := b.Create(t.Context(), "namespace", transaction("c")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := b.Get(ctx, "namespace", "b"); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored canceled context")
	}
	changed := *cfg
	changed.Capacity++
	if other, err := storage.New(t.Context(), &changed); err == nil {
		other.Close()
		t.Fatal("inconsistent limits accepted")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(t.Context(), "namespace", "b"); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("closed backend usable")
	}
}

func TestSQLiteLoginExpiry(t *testing.T) {
	cfg := storeConfig(t)
	a, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	tx := transaction("expires")
	tx.CreatedAt = time.Now().Add(-time.Minute).Unix()
	tx.ExpiresAt = time.Now().Add(2 * time.Second).Unix()
	if err := a.Create(t.Context(), "namespace", tx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Claim(t.Context(), "namespace", tx.State, tx.Binding, "claim"); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(time.Unix(tx.ExpiresAt, 0)))
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal("expiry test canceled")
	case <-timer.C:
	}
	if err := a.Complete(t.Context(), "namespace", tx.State, "claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("expired claimed transaction completed")
	}
	if _, err := b.Get(t.Context(), "namespace", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("expired evidence returned")
	}
	if ok, err := a.Cancel(t.Context(), "namespace", tx.State, tx.Binding); err != nil || ok {
		t.Fatal("expired login remained active")
	}
	for _, state := range []string{"fresh-a", "fresh-b"} {
		if err := b.Create(t.Context(), "namespace", transaction(state)); err != nil {
			t.Fatal("expiry did not release capacity")
		}
	}
}

func TestSQLiteLoginRecordSize(t *testing.T) {
	cfg := storeConfig(t)
	a, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := storage.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	value := transaction("boundary")
	claim := strings.Repeat("&", 128)
	value.Claim = claim
	value.ReturnURL = "/" + strings.Repeat("&", 10000)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the 64 KiB persisted-record budget with the largest encoded claim.
	value.ReturnURL += strings.Repeat("a", 65536-len(encoded))
	if err := value.Validate(time.Now()); err != nil {
		t.Fatal("boundary fixture is not valid transaction evidence")
	}
	value.Claim = ""
	if err := a.Create(t.Context(), "namespace", value); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Claim(t.Context(), "namespace", value.State, value.Binding, claim); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get(t.Context(), "namespace", value.State)
	if err != nil || got.Claim != claim || got.ReturnURL != value.ReturnURL {
		t.Fatal("accepted transaction became unreadable after claiming")
	}
	if err := b.Complete(t.Context(), "namespace", value.State, claim); err != nil {
		t.Fatal(err)
	}
	value.ReturnURL += "a"
	if err := a.Create(t.Context(), "namespace", value); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("creation did not reserve room for a valid claim")
	}
	if _, err := b.Get(t.Context(), "namespace", value.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("rejected oversized transaction was published")
	}
}
