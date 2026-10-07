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
	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPassword = "Synthetic-password-2026!"

func fixture(t *testing.T) (*Store, *Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Name: "accounts", Realm: "staff", Path: filepath.Join(dir, "accounts.db"), Timeout: "5s"}
	store, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, cfg
}
func provision(t *testing.T, s *Store) (*Account, string, []byte) {
	t.Helper()
	a := &Account{Username: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"viewer"}}
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := uuid.NewString()
	if _, err := s.CreateEnrollment(t.Context(), enrollment, a, hash); err != nil {
		t.Fatal(err)
	}
	return a, enrollment, hash
}
func authenticate(t *testing.T, s *Store, password string) requests.AuthenticationEvidence {
	t.Helper()
	r := &requests.Request{Upstream: requests.Upstream{Realm: "staff"}, User: requests.User{Username: "ALICE@example.test", Password: password}}
	if err := s.Request(operator.Authenticate, r); err != nil {
		t.Fatal(err)
	}
	if r.Authentication.AuthenticatedAt == 0 || r.Authentication.Method != "pwd" || r.User.Username != "alice" {
		t.Fatal("invalid authentication proof")
	}
	return r.Authentication
}
func TestIdentityEvidenceMutationsAndPersistence(t *testing.T) {
	s, c := fixture(t)
	a, enrollment, hash := provision(t, s)
	proof := authenticate(t, s, testPassword)
	first, err := s.CreateEnrollment(t.Context(), enrollment, a, hash)
	if err != nil || first["id"] != proof.UserID {
		t.Fatal("enrollment was not idempotent", err)
	}
	altered := *a
	altered.Email = "other@example.test"
	if _, err := s.CreateEnrollment(t.Context(), enrollment, &altered, hash); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	other, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.DisableUser("alice", "wrong@example.test"); !errors.Is(err, ErrDenied) {
		t.Fatal("identity pair not checked", err)
	}
	if err := other.DisableUser("alice", a.Email); err != nil {
		t.Fatal(err)
	}
	called := false
	apply := func(identity.RefreshIdentity) error { called = true; return nil }
	if err := s.WithRefreshIdentity(t.Context(), proof, apply); !errors.Is(err, identity.ErrRefreshIdentityDenied) || called {
		t.Fatal("disabled proof accepted", err)
	}
	if err := other.EnableUser("alice", a.Email); err != nil {
		t.Fatal(err)
	}
	if err := s.WithRefreshIdentity(t.Context(), proof, apply); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("old proof revived", err)
	}
	proof = authenticate(t, s, testPassword)
	if err := other.SetPassword(t.Context(), "alice", a.Email, "Replacement-password-2026!"); err != nil {
		t.Fatal(err)
	}
	if err := s.WithRefreshIdentity(t.Context(), proof, apply); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("password proof survived", err)
	}
	proof = authenticate(t, s, "Replacement-password-2026!")
	if _, err := other.OverwriteUserRoles("alice", a.Email, []string{"changed"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithRefreshIdentity(t.Context(), proof, apply); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("role proof survived", err)
	}
	proof = authenticate(t, s, "Replacement-password-2026!")
	if err := other.WithRefreshIdentity(t.Context(), proof, apply); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("foreign instance epoch accepted", err)
	}
	if err := s.WithRefreshIdentity(t.Context(), proof, func(a identity.RefreshIdentity) error {
		if len(a.Roles) != 1 || a.Roles[0] != "changed" {
			t.Fatal("stale roles")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := other.DeleteUser("alice", a.Email); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnrollment(t.Context(), enrollment, a, hash); !errors.Is(err, ErrDenied) {
		t.Fatal("replay resurrected deleted account", err)
	}
	replacement, err := s.Create(t.Context(), a, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if replacement["id"] == proof.UserID {
		t.Fatal("recreated identity reused ID")
	}
	if err := s.WithRefreshIdentity(t.Context(), proof, apply); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("deleted proof survived", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	authenticate(t, reopened, testPassword)
}
func TestIdentityValidationAndFailureEvidence(t *testing.T) {
	s, _ := fixture(t)
	a, _, _ := provision(t, s)
	for _, password := range []string{"", "short", string(make([]byte, 73))} {
		if _, err := HashPassword(password); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid password accepted")
		}
	}
	for _, input := range []*Account{nil, {Username: "nobody", Email: a.Email, Roles: a.Roles}, {Username: "bad username", Email: a.Email, Roles: a.Roles}, {Username: "alice", Email: "Name <a@example.test>", Roles: a.Roles}, {Username: "alice", Email: a.Email, Roles: nil}} {
		if _, err := s.Create(t.Context(), input, testPassword); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid account accepted", err)
		}
	}
	for _, name := range []string{"alice", "missing"} {
		r := &requests.Request{User: requests.User{Username: name, Password: "incorrect-password"}, Authentication: requests.AuthenticationEvidence{UserID: "stale"}, Response: requests.Response{Authenticated: true}}
		if err := s.Request(operator.Authenticate, r); !errors.Is(err, ErrDenied) || r.Authentication.UserID != "" || r.Response.Authenticated {
			t.Fatal("failed authentication retained evidence", err)
		}
	}
	if err := s.Request(operator.GetMfaTokens, &requests.Request{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := s.OverwriteUserAuthChallengeRules("alice", a.Email, []string{"password"}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Create(ctx, a, testPassword); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	metadata, err := s.FetchUserData("alice", a.Email)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := metadata["password"]; exists {
		t.Fatal("credential leak")
	}
	metadata["roles"].([]string)[0] = "changed"
	fresh, err := s.FetchUserData("alice", a.Email)
	if err != nil || fresh["roles"].([]string)[0] != "viewer" {
		t.Fatal("aliased roles", err)
	}
	rows, err := s.GetUsersMetadata("")
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	r := &requests.Request{User: requests.User{Username: "alice", Password: testPassword}}
	if err := s.Request(operator.Authenticate, r); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func TestIdentitySerializesIssuanceAndMutation(t *testing.T) {
	s, c := fixture(t)
	provision(t, s)
	proof := authenticate(t, s, testPassword)
	other, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	err = s.WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err := other.mutate(ctx, "alice", "alice@example.test", func(ctx context.Context, tx *sql.Tx, a accountRecord) error {
			_, err := tx.ExecContext(ctx, "UPDATE accounts SET enabled=0 WHERE id=?", a.id)
			return err
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("mutation crossed issuance transaction: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticate(t, s, testPassword)
	if err := other.DisableUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error { return nil }); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal(err)
	}
}

func TestIdentityManagementAndSupportedOperations(t *testing.T) {
	s, _ := fixture(t)
	created, err := s.AddUser("alice", "alice@example.test", "Alice", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	authenticate(t, s, created["password"].(string))
	reset, err := s.ResetUserPassword("alice", "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	authenticate(t, s, reset["password"].(string))
	if reset["password"] == created["password"] {
		t.Fatal("password reset reused secret")
	}
	r := &requests.Request{User: requests.User{Username: "missing", FullName: "stale", Roles: []string{"admin"}}}
	if err := s.Request(operator.IdentifyUser, r); err != nil || r.Authentication.UserID != "" || len(r.User.Roles) != 0 || r.User.FullName != "" {
		t.Fatal("unknown identification retained authority", err)
	}
	if err := s.Request(operator.Authenticate, &requests.Request{Upstream: requests.Upstream{Realm: "other"}, User: requests.User{Username: "alice", Password: reset["password"].(string)}}); !errors.Is(err, ErrDenied) {
		t.Fatal("cross-realm account", err)
	}
	if !s.Configured() || s.Reload() != nil {
		t.Fatal("configured store unavailable")
	}
	metadata, err := s.GetMetadata("")
	if err != nil || metadata["kind"] != "sqlite" {
		t.Fatal(err)
	}
	if _, err := s.AddUserRoles("alice", "alice@example.test", []string{"extra"}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := New(t.Context(), nil); err == nil {
		t.Fatal("nil config accepted")
	}
}
