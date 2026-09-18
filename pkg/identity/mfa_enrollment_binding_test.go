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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newMFABindingTestDatabase(t *testing.T, inMemory bool) (*Database, *requests.Request) {
	t.Helper()
	path := ":memory:"
	if !inMemory {
		path = filepath.Join(t.TempDir(), "users.json")
	}
	db, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &requests.Request{User: requests.User{
		Username: tests.TestUser1, Email: tests.TestEmail1, Password: tests.TestPwd1,
		Roles: []string{"authp/user"},
	}}
	if err := db.AddUser(r); err != nil {
		t.Fatal(err)
	}
	if err := db.AuthenticateUser(r); err != nil {
		t.Fatal(err)
	}
	return db, r
}

func mfaBindingTestRequest(authenticated *requests.Request, label string) *requests.Request {
	return &requests.Request{
		User:           requests.User{Username: authenticated.User.Username, Email: authenticated.User.Email},
		Authentication: authenticated.Authentication,
		MfaToken: requests.MfaToken{
			Type: "totp", Secret: "binding-secret-" + label, Comment: label,
			Period: 30, Digits: 6, Algorithm: "sha1", SkipVerification: true,
		},
	}
}

func mutateBoundMFA(db *Database, r *requests.Request, enrollment bool) error {
	if enrollment {
		return db.EnrollMfaToken(r)
	}
	return db.AddMfaToken(r)
}

func TestDatabaseMFAMutationAcceptsCurrentAuthenticationEvidence(t *testing.T) {
	for _, inMemory := range []bool{true, false} {
		for _, enrollment := range []bool{false, true} {
			name := "file_add"
			if inMemory {
				name = "memory_add"
			}
			if enrollment {
				name += "_enrollment"
			}
			t.Run(name, func(t *testing.T) {
				db, authenticated := newMFABindingTestDatabase(t, inMemory)
				if err := mutateBoundMFA(db, mfaBindingTestRequest(authenticated, name), enrollment); err != nil {
					t.Fatalf("current authentication evidence rejected: %v", err)
				}
				if got := len(db.Users[0].MfaTokens); got != 1 {
					t.Fatalf("MFA token count: got %d, want 1", got)
				}
			})
		}
	}
}

func TestDatabaseMFAMutationRejectsChangedIdentity(t *testing.T) {
	for _, inMemory := range []bool{true, false} {
		for _, enrollment := range []bool{false, true} {
			for _, change := range []string{"replacement", "credential", "disabled"} {
				name := change
				if inMemory {
					name += "_memory"
				} else {
					name += "_file"
				}
				if enrollment {
					name += "_enrollment"
				} else {
					name += "_add"
				}
				t.Run(name, func(t *testing.T) {
					db, authenticated := newMFABindingTestDatabase(t, inMemory)
					proof := authenticated.Authentication
					switch change {
					case "replacement":
						if err := db.DeleteUser(&requests.Request{User: authenticated.User}); err != nil {
							t.Fatal(err)
						}
						if err := db.AddUser(&requests.Request{User: requests.User{
							Username: authenticated.User.Username, Email: authenticated.User.Email,
							Password: tests.TestPwd1, Roles: []string{"authp/user"},
						}}); err != nil {
							t.Fatal(err)
						}
					case "credential":
						if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
							Username: authenticated.User.Username, Email: authenticated.User.Email,
							OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
						}}); err != nil {
							t.Fatal(err)
						}
					case "disabled":
						if err := db.DisableUser(&requests.Request{User: authenticated.User}); err != nil {
							t.Fatal(err)
						}
					}
					current := db.Users[0]
					beforeCredentialVersion := current.CredentialVersion
					beforeRevision := db.Revision
					r := mfaBindingTestRequest(authenticated, name)
					r.Authentication = proof
					if err := mutateBoundMFA(db, r, enrollment); err == nil {
						t.Fatal("changed identity accepted stale authentication evidence")
					}
					if len(current.MfaTokens) != 0 || current.CredentialVersion != beforeCredentialVersion || db.Revision != beforeRevision {
						t.Fatal("rejected MFA mutation changed the identity")
					}
				})
			}
		}
	}
}

func TestDatabaseMFAMutationRejectsIncompleteAuthenticationEvidence(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, true)
	proof := authenticated.Authentication
	for name, incomplete := range map[string]requests.AuthenticationEvidence{
		"user ID only":         {UserID: proof.UserID},
		"backend version only": {BackendVersion: proof.BackendVersion},
		"method only":          {Method: "pwd"},
	} {
		t.Run(name, func(t *testing.T) {
			r := mfaBindingTestRequest(authenticated, name)
			r.Authentication = incomplete
			if err := db.EnrollMfaToken(r); err == nil {
				t.Fatal("incomplete authentication evidence accepted")
			}
		})
	}
	if len(db.Users[0].MfaTokens) != 0 {
		t.Fatal("incomplete evidence mutated the identity")
	}
}

func TestDatabaseMFAMutationRejectsEvidenceFromPreviousLoad(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	loaded, err := NewDatabase(db.GetPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, enrollment := range []bool{false, true} {
		if err := mutateBoundMFA(loaded, mfaBindingTestRequest(authenticated, "reload"), enrollment); err == nil {
			t.Fatal("authentication evidence survived a backend reload")
		}
	}
	if len(loaded.Users[0].MfaTokens) != 0 {
		t.Fatal("reloaded backend accepted an MFA mutation")
	}
}

func TestDatabaseMFAMutationChecksPersistedIdentityUnderFileLock(t *testing.T) {
	for _, enrollment := range []bool{false, true} {
		t.Run(map[bool]string{false: "add", true: "enroll"}[enrollment], func(t *testing.T) {
			db, authenticated := newMFABindingTestDatabase(t, false)
			other, err := NewDatabase(db.GetPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := other.ChangeUserPassword(&requests.Request{User: requests.User{
				Username: authenticated.User.Username, Email: authenticated.User.Email,
				OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
			}}); err != nil {
				t.Fatal(err)
			}
			if err := mutateBoundMFA(db, mfaBindingTestRequest(authenticated, "persisted"), enrollment); err == nil {
				t.Fatal("stale backend overwrote a persisted credential change")
			}
			persisted, err := NewDatabase(db.GetPath())
			if err != nil {
				t.Fatal(err)
			}
			if len(persisted.Users[0].MfaTokens) != 0 || persisted.Users[0].CredentialVersion != other.Users[0].CredentialVersion {
				t.Fatal("rejected mutation changed the persisted identity")
			}
		})
	}
}

func TestDatabaseBoundMFAEnrollmentPreservesOtherPersistedChanges(t *testing.T) {
	t.Run("other user credential change", func(t *testing.T) {
		db, authenticated := newMFABindingTestDatabase(t, false)
		bob := &requests.Request{User: requests.User{
			Username: "bob", Email: "bob@example.test", Password: tests.TestPwd1,
			Roles: []string{"authp/user"},
		}}
		if err := db.AddUser(bob); err != nil {
			t.Fatal(err)
		}
		other, err := NewDatabase(db.GetPath())
		if err != nil {
			t.Fatal(err)
		}
		if err := other.ChangeUserPassword(&requests.Request{User: requests.User{
			Username: bob.User.Username, Email: bob.User.Email,
			OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
		}}); err != nil {
			t.Fatal(err)
		}
		bobVersion := other.Users[1].CredentialVersion
		if err := db.EnrollMfaToken(mfaBindingTestRequest(authenticated, "preserve-bob")); err != nil {
			t.Fatalf("bound enrollment failed: %v", err)
		}
		for _, current := range []*Database{db, mustLoadMFABindingDatabase(t, db.GetPath())} {
			alice, err := current.findUserIdentity(authenticated.User.Username, authenticated.User.Email)
			if err != nil || len(alice.MfaTokens) != 1 {
				t.Fatal("Alice enrollment was not retained", err)
			}
			currentBob, err := current.findUserIdentity(bob.User.Username, bob.User.Email)
			if err != nil || currentBob.CredentialVersion != bobVersion {
				t.Fatal("Bob credential change was overwritten", err)
			}
		}
	})

	t.Run("same user role change", func(t *testing.T) {
		db, authenticated := newMFABindingTestDatabase(t, false)
		other, err := NewDatabase(db.GetPath())
		if err != nil {
			t.Fatal(err)
		}
		if err := other.OverwriteUserRoles(&requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email,
			Roles: []string{"authp/user", "authp/admin"},
		}}); err != nil {
			t.Fatal(err)
		}
		if got := other.Users[0].CredentialVersion; got == authenticated.Authentication.CredentialVersion {
			t.Fatal("role update did not revoke existing identity evidence")
		}
		current := &requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd1,
		}}
		if err := db.AuthenticateUser(current); err != nil {
			t.Fatal(err)
		}
		if err := db.EnrollMfaToken(mfaBindingTestRequest(current, "preserve-role")); err != nil {
			t.Fatalf("bound enrollment failed: %v", err)
		}
		for _, current := range []*Database{db, mustLoadMFABindingDatabase(t, db.GetPath())} {
			alice, err := current.findUserIdentity(authenticated.User.Username, authenticated.User.Email)
			if err != nil || len(alice.MfaTokens) != 1 {
				t.Fatal("Alice enrollment was not retained", err)
			}
			roles := alice.GetRolesClaim()
			if len(roles) != 2 || roles[0] != "authp/admin" && roles[1] != "authp/admin" {
				t.Fatalf("Alice role change was overwritten: %v", roles)
			}
		}
	})
}

func TestDatabaseBoundMFAMutationNormalizesLegacySnapshot(t *testing.T) {
	for _, enrollment := range []bool{false, true} {
		t.Run(map[bool]string{false: "add", true: "enroll"}[enrollment], func(t *testing.T) {
			db, authenticated := newMFABindingTestDatabase(t, false)
			db.mu.Lock()
			db.Policy = Policy{}
			db.Version = ""
			db.Users[0].Passwords[0].Algorithm = ""
			err := db.commit()
			db.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}

			if err := mutateBoundMFA(db, mfaBindingTestRequest(authenticated, "legacy"), enrollment); err != nil {
				t.Fatalf("bound MFA mutation failed: %v", err)
			}
			if db.Policy != defaultPolicy || db.Version != app.Version || db.Users[0].Passwords[0].Algorithm != "bcrypt" {
				t.Fatal("live database did not adopt normalized legacy fields")
			}
			login := &requests.Request{User: requests.User{
				Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd1,
			}}
			if err := db.AuthenticateUser(login); err != nil {
				t.Fatalf("legacy password stopped authenticating: %v", err)
			}

			data, err := os.ReadFile(db.GetPath())
			if err != nil {
				t.Fatal(err)
			}
			persisted := new(Database)
			if err := json.Unmarshal(data, persisted); err != nil {
				t.Fatal(err)
			}
			if persisted.Policy != defaultPolicy || persisted.Version != app.Version || persisted.Users[0].Passwords[0].Algorithm != "bcrypt" {
				t.Fatal("normalized legacy fields were not persisted")
			}
		})
	}
}

func mustLoadMFABindingDatabase(t *testing.T, path string) *Database {
	t.Helper()
	db, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestDatabaseBoundMFACommitFailureRollsBack(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, true)
	r := mfaBindingTestRequest(authenticated, "rollback")
	user := db.Users[0]
	previousCredentialVersion := user.CredentialVersion
	previousUserRevision := user.Revision
	previousDatabaseRevision := db.Revision

	db.mu.Lock()
	bound, err := db.validateMfaTokenMutationEvidence(r.Authentication, user)
	if err != nil || !bound {
		db.mu.Unlock()
		t.Fatal("valid evidence did not bind the mutation", err)
	}
	commitErr := errors.New("synthetic commit failure")
	err = db.addMfaTokenUnlocked(r, false, func() error { return commitErr })
	db.mu.Unlock()
	if err == nil {
		t.Fatal("MFA mutation succeeded despite commit failure")
	}
	if len(user.MfaTokens) != 0 || user.CredentialVersion != previousCredentialVersion ||
		user.Revision != previousUserRevision || db.Revision != previousDatabaseRevision {
		t.Fatal("commit failure left an unpersisted MFA mutation")
	}
}
