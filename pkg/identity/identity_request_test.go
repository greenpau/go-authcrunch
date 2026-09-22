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
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func identityRequest(t *testing.T, authenticated *requests.Request) *requests.Request {
	t.Helper()
	return &requests.Request{
		User:           requests.User{Username: authenticated.User.Username, Email: authenticated.User.Email},
		Authentication: authenticated.Authentication,
	}
}

func TestDatabaseRequestWithIdentityDetachesResponse(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	r := identityRequest(t, authenticated)
	if err := db.RequestWithIdentity(operator.GetUser, r); err != nil {
		t.Fatal(err)
	}
	got, ok := r.Response.Payload.(*User)
	if !ok {
		t.Fatalf("unexpected response payload %T", r.Response.Payload)
	}
	got.Username = "attacker"
	if db.Users[0].Username != authenticated.User.Username {
		t.Fatal("profile response retained a mutable live identity pointer")
	}
}

func TestDatabaseRequestWithIdentityPersistsBoundMutation(t *testing.T) {
	for _, inMemory := range []bool{true, false} {
		t.Run(map[bool]string{true: "memory", false: "file"}[inMemory], func(t *testing.T) {
			db, authenticated := newMFABindingTestDatabase(t, inMemory)
			r := identityRequest(t, authenticated)
			secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
			r.Key = requests.Key{Usage: "api", Payload: secret, Comment: "bound key"}
			if err := db.RequestWithIdentity(operator.AddAPIKey, r); err != nil {
				t.Fatal(err)
			}
			lookupDB := db
			if !inMemory {
				lookupDB = mustLoadMFABindingDatabase(t, db.GetPath())
			}
			lookup := &requests.Request{Key: requests.Key{Payload: secret}}
			if err := lookupDB.LookupAPIKey(lookup); err != nil || lookup.User.Username != authenticated.User.Username {
				t.Fatal("bound API key mutation was not retained", err)
			}
		})
	}
}

func TestDatabaseRequestWithIdentityRejectsPasswordHashImports(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	proof := authenticated.Authentication
	before := passwordMutationSnapshot(t, db.Users[0])
	beforeRevision := db.Revision
	beforeFile, err := os.ReadFile(db.GetPath())
	if err != nil {
		t.Fatal(err)
	}
	for i, candidate := range []string{
		tests.TestPwd2Hash(t),
		"bcrypt:malformed",
		"argon2:" + argon2ReferenceHash,
		" \targon2:malformed\n",
	} {
		r := identityRequest(t, authenticated)
		r.User.OldPassword = tests.TestPwd1
		r.User.Password = candidate
		if err := db.RequestWithIdentity(operator.ChangePassword, r); err == nil {
			t.Errorf("self-service password hash import case %d was accepted", i)
		}
		if got := passwordMutationSnapshot(t, db.Users[0]); !bytes.Equal(got, before) {
			t.Fatal("rejected self-service password import changed credential state")
		}
		if db.Revision != beforeRevision {
			t.Fatal("rejected self-service password import advanced the database revision")
		}
		persisted, err := os.ReadFile(db.GetPath())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(persisted, beforeFile) {
			t.Fatal("rejected self-service password import changed the persisted database")
		}
		if err := db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { return nil }); err != nil {
			t.Fatal("rejected self-service password import revoked current evidence", err)
		}
	}

	r := identityRequest(t, authenticated)
	r.User.OldPassword = tests.TestPwd1
	r.User.Password = tests.TestPwd2
	if err := db.RequestWithIdentity(operator.ChangePassword, r); err != nil {
		t.Fatal("ordinary self-service password change failed", err)
	}
	if db.Users[0].VerifyPassword(tests.TestPwd2) != nil || db.Users[0].CredentialVersion != proof.CredentialVersion+1 {
		t.Fatal("ordinary self-service password change did not persist and revoke evidence")
	}
	if err := db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { return nil }); !errors.Is(err, ErrRefreshIdentityDenied) {
		t.Fatal("ordinary self-service password change retained stale evidence", err)
	}
}

func TestDatabaseRequestWithIdentityRejectsWrongOrStaleIdentity(t *testing.T) {
	t.Run("cross account", func(t *testing.T) {
		db, authenticated := newMFABindingTestDatabase(t, false)
		bob := &requests.Request{User: requests.User{
			Username: "bob", Email: "bob@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"},
		}}
		if err := db.AddUser(bob); err != nil {
			t.Fatal(err)
		}
		r := identityRequest(t, authenticated)
		r.User = requests.User{Username: bob.User.Username, Email: bob.User.Email}
		if err := db.RequestWithIdentity(operator.GetUser, r); !errors.Is(err, ErrIdentityRequestDenied) {
			t.Fatal("cross-account identity request was not denied", err)
		}
	})

	for _, change := range []string{"revoked", "deleted and recreated"} {
		t.Run(change, func(t *testing.T) {
			stale, authenticated := newMFABindingTestDatabase(t, false)
			current := mustLoadMFABindingDatabase(t, stale.GetPath())
			switch change {
			case "revoked":
				if err := current.RevokeUserSessions(t.Context(), authenticated.Authentication.UserID); err != nil {
					t.Fatal(err)
				}
			case "deleted and recreated":
				if err := current.DeleteUser(&requests.Request{User: authenticated.User}); err != nil {
					t.Fatal(err)
				}
				if err := current.AddUser(&requests.Request{User: requests.User{
					Username: authenticated.User.Username, Email: authenticated.User.Email,
					Password: tests.TestPwd1, Roles: []string{"authp/user"},
				}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := stale.RequestWithIdentity(operator.GetUser, identityRequest(t, authenticated)); !errors.Is(err, ErrIdentityRequestDenied) {
				t.Fatal("stale identity request was not denied", err)
			}
		})
	}

	t.Run("locked", func(t *testing.T) {
		db, authenticated := newMFABindingTestDatabase(t, true)
		db.Users[0].Lockout = &LockoutState{Enabled: true, EndTime: time.Now().Add(time.Minute)}
		if err := db.RequestWithIdentity(operator.GetUser, identityRequest(t, authenticated)); !errors.Is(err, ErrIdentityRequestDenied) {
			t.Fatal("locked identity request was not denied", err)
		}
	})

	t.Run("missing evidence", func(t *testing.T) {
		db, authenticated := newMFABindingTestDatabase(t, true)
		r := identityRequest(t, authenticated)
		r.Authentication = requests.AuthenticationEvidence{}
		if err := db.RequestWithIdentity(operator.GetUser, r); !errors.Is(err, ErrIdentityRequestDenied) {
			t.Fatal("identity request without evidence was not denied", err)
		}
	})

	t.Run("unsupported operation", func(t *testing.T) {
		db, authenticated := newMFABindingTestDatabase(t, true)
		if err := db.RequestWithIdentity(operator.Authenticate, identityRequest(t, authenticated)); !errors.Is(err, ErrIdentityRequestDenied) {
			t.Fatal("unsupported identity operation was not denied", err)
		}
	})
}

func TestDatabaseRoleChangesRevokeIdentityEvidence(t *testing.T) {
	for _, inMemory := range []bool{true, false} {
		t.Run(map[bool]string{true: "memory", false: "file"}[inMemory], func(t *testing.T) {
			db, authenticated := newMFABindingTestDatabase(t, inMemory)
			proof := authenticated.Authentication
			if err := db.OverwriteUserRoles(&requests.Request{User: requests.User{
				Username: authenticated.User.Username, Email: authenticated.User.Email, Roles: []string{"removed"},
			}}); err != nil {
				t.Fatal(err)
			}
			if err := db.RequestWithIdentity(operator.GetUser, identityRequest(t, authenticated)); !errors.Is(err, ErrIdentityRequestDenied) {
				t.Fatal("role change did not revoke profile identity evidence", err)
			}
			called := false
			err := db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrRefreshIdentityDenied) || called {
				t.Fatal("role change did not revoke refresh identity evidence", err)
			}
		})
	}
}
