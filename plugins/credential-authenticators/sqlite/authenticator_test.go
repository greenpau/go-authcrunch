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

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Authenticator, *Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := &Config{Name: "keys", Realm: "staff", Path: filepath.Join(dir, "credentials.db")}
	a, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, c
}
func TestCredentialsDurabilityIsolationAndRevocation(t *testing.T) {
	a, c := fixture(t)
	if c.Timeout != "" {
		t.Fatal("constructor modified input")
	}
	key, err := a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := a.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT digest FROM api_keys").Scan(&stored)
	}); err != nil || string(stored) == key || len(stored) != 32 {
		t.Fatal("raw key stored", err)
	}
	check := func(a *Authenticator, key, realm string, want error) {
		t.Helper()
		r := &authproxy.Request{Realm: realm, Secret: key, Response: authproxy.Response{Payload: "stale"}}
		err := a.APIKeyAuth(r)
		if !errors.Is(err, want) {
			t.Fatalf("authentication error %v, want %v", err, want)
		}
		if want != nil && r.Response.Payload != "" {
			t.Fatal("failed response retained claims")
		}
		if want == nil && (!r.Response.IsPlainPayload || r.Response.Payload == "") {
			t.Fatal("missing verified claims")
		}
	}
	check(a, key, "staff", nil)
	check(a, key, "other", ErrDenied)
	check(a, "not-a-key", "staff", ErrDenied)
	other := *c
	other.Realm = "other"
	foreign, err := New(t.Context(), &other)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	check(foreign, key, "other", ErrDenied)
	if err := foreign.Revoke(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	check(a, key, "staff", nil)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	check(a, key, "staff", ErrUnavailable)
	reopened, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	check(reopened, key, "staff", nil)
	if err := reopened.Revoke(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	check(reopened, key, "staff", ErrDenied)
	if err := reopened.Revoke(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	key, err = reopened.Issue(t.Context(), "bob", "bob@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE api_keys SET expires=0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	check(reopened, key, "staff", ErrDenied)
}
func TestCredentialsValidationCancellationAndConcurrency(t *testing.T) {
	a, _ := fixture(t)
	for _, tc := range []struct {
		subject, email string
		roles          []string
		expiry         time.Time
	}{
		{"", "a@example.test", []string{"viewer"}, time.Now().Add(time.Hour)},
		{"alice", "Display <a@example.test>", []string{"viewer"}, time.Now().Add(time.Hour)},
		{"alice", "a@example.test", nil, time.Now().Add(time.Hour)},
		{"alice", "a@example.test", []string{""}, time.Now().Add(time.Hour)},
		{"alice", "a@example.test", []string{"viewer"}, time.Now()},
		{"alice", "a@example.test", []string{"viewer"}, time.Now().Add(31 * 24 * time.Hour)},
	} {
		if key, err := a.Issue(t.Context(), tc.subject, tc.email, tc.roles, tc.expiry); key != "" || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid provisioning accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if key, err := a.Issue(ctx, "alice", "a@example.test", []string{"viewer"}, time.Now().Add(time.Hour)); key != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled provisioning", err)
	}
	r := &authproxy.Request{Response: authproxy.Response{Payload: "stale"}}
	if err := a.BasicAuth(r); !errors.Is(err, ErrDenied) || r.Response.Payload != "" {
		t.Fatal("Basic accepted")
	}
	if err := a.APIKeyAuth(nil); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			key, err := a.Issue(t.Context(), "alice", "a@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
			if err != nil {
				t.Error(err)
				return
			}
			r := &authproxy.Request{Secret: key, Realm: "staff"}
			if err := a.APIKeyAuthContext(t.Context(), r); err != nil {
				t.Error(err)
			}
			if err := a.Revoke(t.Context(), key); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	metadata := a.GetConfig()
	metadata["name"] = "mutated"
	if a.GetName() != "keys" || a.GetConfig()["name"] != "keys" {
		t.Fatal("metadata aliases configuration")
	}
	if _, err := New(t.Context(), nil); err == nil {
		t.Fatal("nil config accepted")
	}
}
