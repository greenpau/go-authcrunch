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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These helpers seed token-verifier tests through the same storage contract.
// They are not runtime APIs and never bypass callback checks in production.
func (s *MemoryLoginStore) add(state, nonce string) error {
	return s.addLogin(state, nonce, "verifier", "browser", "https://portal.example/callback", "")
}
func (s *MemoryLoginStore) addLogin(state, nonce, verifier, browser, callback, destination string) error {
	tx := testLoginTransaction(state)
	tx.Nonce, tx.NonceRequired, tx.Verifier = nonce, nonce != "", verifier
	tx.Binding = LoginBinding{Browser: sha256.Sum256([]byte(browser)), Callback: callback}
	tx.ReturnURL = destination
	return s.Create(context.Background(), "", tx)
}
func (s *MemoryLoginStore) beginCallback(state, browser, callback string) bool {
	_, err := s.Claim(context.Background(), "", state, LoginBinding{Browser: sha256.Sum256([]byte(browser)), Callback: callback}, "test-claim")
	return err == nil
}
func (s *MemoryLoginStore) requiresNonce(state string) (bool, error) {
	tx, err := s.Get(context.Background(), "", state)
	return tx.NonceRequired, err
}
func testLoginTransaction(state string) LoginTransaction {
	now := time.Now()
	return LoginTransaction{State: state, Nonce: "nonce", NonceRequired: true, Verifier: "private-verifier",
		Binding:   LoginBinding{Browser: sha256.Sum256([]byte("browser")), Callback: "https://portal.example/callback"},
		ReturnURL: "/destination", CreatedAt: now.Unix(), ExpiresAt: now.Add(oauthLoginLifetime).Unix()}
}

func TestLoginStoreLifecycle(t *testing.T) {
	s := NewMemoryLoginStore()
	tx := testLoginTransaction("state")
	if err := s.Create(t.Context(), "portal", tx); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(t.Context(), "portal", tx); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("duplicate replaced login")
	}
	if _, err := s.Get(t.Context(), "other", tx.State); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("namespace leaked")
	}
	wrong := tx.Binding
	wrong.Browser = sha256.Sum256([]byte("another browser"))
	if _, err := s.Claim(t.Context(), "portal", tx.State, wrong, "claim"); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("wrong browser admitted")
	}
	wrong = tx.Binding
	wrong.Callback += "/other"
	if canceled, err := s.Cancel(t.Context(), "portal", tx.State, wrong); err != nil || canceled {
		t.Fatal("wrong endpoint canceled login")
	}
	claimed, err := s.Claim(t.Context(), "portal", tx.State, tx.Binding, "claim")
	if err != nil || claimed.Nonce != tx.Nonce || claimed.Verifier != tx.Verifier || claimed.ReturnURL != tx.ReturnURL || claimed.Claim != "claim" {
		t.Fatal("lost transaction evidence")
	}
	if err := s.Complete(t.Context(), "portal", tx.State, "wrong"); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("wrong claim completed")
	}
	if err := s.Complete(t.Context(), "portal", tx.State, "claim"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), "portal", tx.State); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("completed login retained")
	}
	if _, err := s.Claim(t.Context(), "portal", tx.State, tx.Binding, "replay"); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("replay admitted")
	}
}

func TestLoginStoreConcurrentClaim(t *testing.T) {
	s := NewMemoryLoginStore()
	tx := testLoginTransaction("state")
	if err := s.Create(t.Context(), "", tx); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := s.Claim(t.Context(), "", tx.State, tx.Binding, "claim"); err == nil {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("admitted %d callbacks", winners.Load())
	}
	if ok, err := s.Cancel(t.Context(), "", tx.State, tx.Binding); err != nil || !ok {
		t.Fatal("claimed cancellation failed")
	}
	if err := s.Complete(t.Context(), "", tx.State, "claim"); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("canceled transaction completed")
	}
	if ok, err := s.Cancel(t.Context(), "", tx.State, tx.Binding); err != nil || ok {
		t.Fatal("cancellation not idempotent")
	}
}

func TestLoginStoreCapacityExpiryAndContext(t *testing.T) {
	s := NewMemoryLoginStore()
	s.maxStates = 2
	for i := range 2 {
		if err := s.Create(t.Context(), "", testLoginTransaction(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Create(t.Context(), "", testLoginTransaction("extra")); !errors.Is(err, ErrLoginCapacity) {
		t.Fatal("capacity not enforced")
	}
	key := loginKey{"", "0"}
	expired := s.entries[key]
	expired.ExpiresAt = time.Now().Unix()
	s.entries[key] = expired
	if _, err := s.Claim(t.Context(), "", "0", expired.Binding, "claim"); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("expired transaction admitted before cleanup")
	}
	if err := s.Create(t.Context(), "", testLoginTransaction("extra")); err != nil {
		t.Fatal("expired capacity not released")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Create(ctx, "", testLoginTransaction("cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
	if _, err := s.Get(ctx, "", "1"); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored read cancellation")
	}
	if _, err := s.Cancel(ctx, "", "1", testLoginTransaction("1").Binding); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored mutation cancellation")
	}
	if _, err := s.Get(t.Context(), "", "1"); err != nil {
		t.Fatal("cancellation mutated existing transaction")
	}
}

func TestLoginTransactionValidation(t *testing.T) {
	now := time.Now()
	skewed := testLoginTransaction("clock-skew")
	skewed.CreatedAt = now.Add(time.Second).Unix()
	skewed.ExpiresAt = skewed.CreatedAt + int64(oauthLoginLifetime/time.Second)
	if err := skewed.Validate(now); err != nil {
		t.Fatal("small replica clock difference rejected valid evidence")
	}
	if err := skewed.Validate(time.Unix(skewed.ExpiresAt, 0)); !errors.Is(err, ErrLoginInvalid) {
		t.Fatal("creation skew tolerance extended the expiry deadline")
	}
	for _, mutate := range []func(*LoginTransaction){
		func(v *LoginTransaction) { v.State = "" }, func(v *LoginTransaction) { v.Binding.Browser = [32]byte{} },
		func(v *LoginTransaction) { v.Binding.Callback = "" }, func(v *LoginTransaction) { v.NonceRequired = false },
		func(v *LoginTransaction) { v.CreatedAt = time.Now().Add(time.Minute).Unix() },
		func(v *LoginTransaction) { v.ExpiresAt = v.CreatedAt + 3600 }, func(v *LoginTransaction) { v.ExpiresAt = time.Now().Unix() },
		func(v *LoginTransaction) { v.ReturnURL = "/bad\nlocation" },
	} {
		tx := testLoginTransaction("state")
		mutate(&tx)
		if tx.Validate(time.Now()) == nil {
			t.Fatal("invalid evidence accepted")
		}
	}
	var s MemoryLoginStore
	if err := s.Create(t.Context(), "", testLoginTransaction("zero-value")); err != nil {
		t.Fatal(err)
	}
	var absent *MemoryLoginStore
	if _, err := absent.Get(t.Context(), "", "state"); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatal("nil store did not fail closed")
	}
}
