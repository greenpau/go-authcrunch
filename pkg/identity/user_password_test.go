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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func passwordMutationFixture(t *testing.T, candidate string) *Password {
	t.Helper()
	p, err := NewPasswordWithOptions(candidate, "generic", "bcrypt", map[string]interface{}{"cost": 8})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func passwordMutationSnapshot(t *testing.T, user *User) []byte {
	t.Helper()
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func applyPasswordMutation(user *User, operation, candidate, old string) error {
	r := &requests.Request{User: requests.User{Password: candidate, OldPassword: old}}
	switch operation {
	case "add":
		return user.AddPassword(candidate, 0)
	case "reset":
		return user.ResetPassword(candidate, 0)
	case "change":
		return user.ChangePassword(r, 0)
	case "update":
		return user.UpdatePassword(r, 0)
	}
	return fmt.Errorf("unknown password operation %q", operation)
}

func TestUserAddPasswordIdempotent(t *testing.T) {
	for _, kind := range []string{"plaintext", "padded plaintext", "import", "padded import"} {
		t.Run(kind, func(t *testing.T) {
			user := NewUser(tests.TestUser1)
			current := passwordMutationFixture(t, tests.TestPwd1)
			history := passwordMutationFixture(t, tests.TestPwd2)
			history.Disable()
			user.Passwords = []*Password{current, history}
			candidate := tests.TestPwd1
			if strings.Contains(kind, "import") {
				candidate = fmt.Sprintf("bcrypt:%d:%s", current.Cost, current.Hash)
			}
			if strings.HasPrefix(kind, "padded") {
				candidate = " \t" + candidate + "\n "
			}
			before := passwordMutationSnapshot(t, user)
			for i := 0; i < 3; i++ {
				if err := user.AddPassword(candidate, 0); err != nil {
					t.Fatal(err)
				}
			}
			if user.Passwords[0] != current || !bytes.Equal(before, passwordMutationSnapshot(t, user)) {
				t.Fatal("duplicate changed the hash, password history, timestamps, or user revision")
			}
			if err := user.VerifyPassword(tests.TestPwd1); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUserPasswordMutationSameSecret(t *testing.T) {
	for _, operation := range []string{"add", "reset", "change", "update"} {
		for _, state := range []string{"active", "disabled", "expired"} {
			for _, kind := range []string{"plaintext", "import"} {
				t.Run(operation+"/"+state+"/"+kind, func(t *testing.T) {
					user := NewUser(tests.TestUser1)
					current := passwordMutationFixture(t, tests.TestPwd1)
					current.Disabled = state == "disabled"
					current.Expired = state == "expired"
					other := passwordMutationFixture(t, tests.TestPwd2)
					user.Passwords = []*Password{current, other}
					candidate := tests.TestPwd1
					if kind == "import" {
						candidate = fmt.Sprintf("bcrypt:%d:%s", current.Cost, current.Hash)
					}
					if err := applyPasswordMutation(user, operation, candidate, tests.TestPwd2); err != nil {
						t.Fatal(err)
					}
					if err := user.VerifyPassword(tests.TestPwd1); err != nil {
						t.Fatal("successful mutation left the requested password unusable:", err)
					}
					if err := user.VerifyPassword(tests.TestPwd2); err == nil || !other.Disabled {
						t.Fatal("successful mutation retained another active password")
					}
					if operation == "reset" || state != "active" {
						if user.Passwords[0] == current || !current.Disabled {
							t.Fatal("reset or inactive credential did not receive a fresh active record")
						}
					} else if user.Passwords[0] != current {
						t.Fatal("matching active credential unnecessarily replaced")
					}
				})
			}
		}
	}
}

func TestUserPasswordMutationDifferentSecret(t *testing.T) {
	for _, operation := range []string{"add", "reset", "change", "update"} {
		for _, kind := range []string{"plaintext", "import"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				user := NewUser(tests.TestUser1)
				current := passwordMutationFixture(t, tests.TestPwd1)
				user.Passwords = []*Password{current}
				candidate := tests.TestPwd2
				if kind == "import" {
					replacement := passwordMutationFixture(t, tests.TestPwd2)
					candidate = fmt.Sprintf("bcrypt:%d:%s", replacement.Cost, replacement.Hash)
				}
				if err := applyPasswordMutation(user, operation, candidate, tests.TestPwd1); err != nil {
					t.Fatal(err)
				}
				if err := user.VerifyPassword(tests.TestPwd2); err != nil {
					t.Fatal(err)
				}
				if err := user.VerifyPassword(tests.TestPwd1); err == nil || !current.Disabled {
					t.Fatal("old password survived replacement")
				}
				if len(user.Passwords) != 2 || user.Passwords[1] != current {
					t.Fatal("replacement did not retain the disabled history record")
				}
			})
		}
	}
}

func TestUserPasswordMutationInvalidInput(t *testing.T) {
	for _, operation := range []string{"add", "reset", "change", "update"} {
		for _, tc := range []struct {
			name      string
			candidate string
		}{
			{name: "empty"},
			{name: "whitespace", candidate: " \t\n"},
			{name: "invalid import", candidate: "bcrypt:"},
			{name: "invalid cost", candidate: "bcrypt:bad:hash"},
			{name: "overlength", candidate: strings.Repeat("x", 73)},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				user := NewUser(tests.TestUser1)
				user.Passwords = []*Password{passwordMutationFixture(t, tests.TestPwd1)}
				before := passwordMutationSnapshot(t, user)
				if err := applyPasswordMutation(user, operation, tc.candidate, tests.TestPwd1); err == nil {
					t.Fatal("invalid replacement accepted")
				}
				if !bytes.Equal(before, passwordMutationSnapshot(t, user)) {
					t.Fatal("failed replacement changed credential state")
				}
			})
		}
	}
}

func TestDatabasePasswordMutationPersistence(t *testing.T) {
	for _, operation := range []string{"reset", "change", "update"} {
		for _, kind := range []string{"plaintext", "import"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				db, err := NewDatabase(filepath.Join(t.TempDir(), "users.json"))
				if err != nil {
					t.Fatal(err)
				}
				password := passwordMutationFixture(t, tests.TestPwd1)
				r := &requests.Request{User: requests.User{
					Username: tests.TestUser1, Email: tests.TestEmail1,
					Password: fmt.Sprintf("bcrypt:%d:%s", password.Cost, password.Hash),
				}}
				if err := db.AddUser(r); err != nil {
					t.Fatal(err)
				}
				r.User.Password = tests.TestPwd1
				if err := db.AuthenticateUser(r); err != nil {
					t.Fatal(err)
				}
				proof := r.Authentication
				current := db.Users[0].Passwords[0]
				if operation == "change" {
					db.Users[0].Passwords = append(db.Users[0].Passwords, passwordMutationFixture(t, tests.TestPwd2))
					r.User.OldPassword = tests.TestPwd2
				}
				if kind == "import" {
					r.User.Password = fmt.Sprintf("bcrypt:%d:%s", current.Cost, current.Hash)
				}
				switch operation {
				case "reset":
					err = db.ResetUserPassword(r)
				case "change":
					err = db.ChangeUserPassword(r)
				case "update":
					// Repeated config/import application must not consume history.
					for i := 0; i < 3; i++ {
						if err = db.UpdateUserPassword(r); err != nil {
							t.Fatal(err)
						}
					}
					if len(db.Users[0].Passwords) != 1 || db.Users[0].Passwords[0] != current {
						t.Fatal("unchanged update rotated password records")
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := db.WithRefreshIdentity(context.Background(), proof, func(RefreshIdentity) error {
					t.Fatal("stale refresh evidence reached issuance")
					return nil
				}); !errors.Is(err, ErrRefreshIdentityDenied) {
					t.Fatal("password mutation retained refresh eligibility:", err)
				}
				loaded, err := NewDatabase(db.GetPath())
				if err != nil {
					t.Fatal(err)
				}
				if loaded.Users[0].CredentialVersion <= proof.CredentialVersion {
					t.Fatal("credential version was not persisted")
				}
				r.User.Password = tests.TestPwd1
				if err := loaded.AuthenticateUser(r); err != nil {
					t.Fatal("persisted replacement password was rejected:", err)
				}
				r.User.Password = tests.TestPwd2
				if err := loaded.AuthenticateUser(r); err == nil {
					t.Fatal("persisted history retained another active password")
				}
			})
		}
	}
}
