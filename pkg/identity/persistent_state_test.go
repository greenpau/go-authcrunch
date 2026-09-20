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

package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func TestPersistentIdentityEpochAndRollback(t *testing.T) {
	db, r := refreshTestDatabase(t)
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(&state.Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.ConfigurePersistentState(s); err != nil {
		t.Fatal(err)
	}
	proof := r.Authentication
	if err = db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { return nil }); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(db.path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	open := func() {
		db, err = NewDatabase(db.path)
		if err != nil {
			t.Fatal(err)
		}
		s, err = state.Open(&state.Config{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		if err = db.ConfigurePersistentState(s); err != nil {
			t.Fatal(err)
		}
	}
	open()
	if err = db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { return nil }); err != nil {
		t.Fatal("unchanged database lost proof epoch", err)
	}
	if err = db.RevokeUserSessions(t.Context(), proof.UserID); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	open()
	if err = db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { t.Fatal("revoked proof accepted"); return nil }); err == nil {
		t.Fatal("credential version not checked")
	}
	_ = s.Close()
	if err = os.WriteFile(db.path, original, 0600); err != nil {
		t.Fatal(err)
	}
	open()
	defer s.Close()
	if err = db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { t.Fatal("rollback restored evidence"); return nil }); err == nil {
		t.Fatal("rollback not detected")
	}
}

func TestPersistentIdentitySelfServiceMutation(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	directory := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.ConfigurePersistentState(storage); err != nil {
		t.Fatal(err)
	}
	r := identityRequest(t, authenticated)
	r.Key = requests.Key{Usage: "api", Payload: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB", Comment: "bound key"}
	if err = db.RequestWithIdentity(operator.AddAPIKey, r); err != nil {
		t.Fatal(err)
	}
	epoch := db.LoadedAt
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDatabase(db.path)
	if err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err = db.ConfigurePersistentState(storage); err != nil {
		t.Fatal(err)
	}
	if !db.LoadedAt.Equal(epoch) {
		t.Fatal("self-service transaction lost durable epoch")
	}
	if err = db.RequestWithIdentity(operator.GetUser, identityRequest(t, authenticated)); err != nil {
		t.Fatal("restart lost completed identity evidence", err)
	}
}

func TestE2EPersistentIdentityConfigurationAdoptsFileChangedBeforeLock(t *testing.T) {
	stale, r := refreshTestDatabase(t)
	current, err := NewDatabase(stale.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = current.RevokeUserSessions(t.Context(), r.Authentication.UserID); err != nil {
		t.Fatal(err)
	}
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err = stale.ConfigurePersistentState(storage); err != nil {
		t.Fatal(err)
	}
	if got := stale.refID[r.Authentication.UserID]; got == nil || got.CredentialVersion == r.Authentication.CredentialVersion {
		t.Fatal("persistence configuration retained the pre-lock identity snapshot")
	}
	currentRequest := requests.NewRequest()
	currentRequest.User.Username = stale.refID[r.Authentication.UserID].Username
	currentRequest.User.Email = stale.refID[r.Authentication.UserID].GetMailClaim()
	if err = stale.GetUser(currentRequest); err != nil {
		t.Fatal("public current-user lookup failed", err)
	}
	currentUser, ok := currentRequest.Response.Payload.(*User)
	if !ok || currentUser.CredentialVersion == r.Authentication.CredentialVersion {
		t.Fatal("public current-user lookup retained stale credential state")
	}
	called := false
	err = stale.WithRefreshIdentity(t.Context(), r.Authentication, func(RefreshIdentity) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("stale identity snapshot retained revoked proof")
	}
}
