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
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func refreshTestDatabase(t *testing.T) (*Database, *requests.Request) {
	t.Helper()
	db, err := NewDatabase(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1, Password: tests.TestPwd1, Roles: []string{"authp/user"}}}
	if err := db.AddUser(r); err != nil {
		t.Fatal(err)
	}
	if err := db.AuthenticateUser(r); err != nil {
		t.Fatal(err)
	}
	return db, r
}

func TestRefreshIdentityEvidenceAndSecurityChanges(t *testing.T) {
	for _, kind := range []string{"password change", "password reset", "password update", "mfa add", "mfa delete", "disable enable", "challenge rules", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			db, r := refreshTestDatabase(t)
			if kind == "mfa delete" {
				r.MfaToken = requests.MfaToken{Type: "totp", Comment: "test", Secret: "0123456789abcdef0123456789abcdef", Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
				if err := db.AddMfaToken(r); err != nil {
					t.Fatal(err)
				}
				if err := db.AuthenticateUser(r); err != nil {
					t.Fatal(err)
				}
				r.MfaToken.ID = db.Users[0].MfaTokens[0].ID
			}
			proof := r.Authentication
			if proof.UserID == "" || proof.AuthenticatedAt == 0 || proof.Method != "pwd" {
				t.Fatal("authentication did not capture evidence")
			}
			called := false
			if err := db.WithRefreshIdentity(context.Background(), proof, func(i RefreshIdentity) error {
				called = true
				if i.Username != tests.TestUser1 {
					t.Fatal("wrong identity")
				}
				return nil
			}); err != nil || !called {
				t.Fatal("valid evidence rejected", err)
			}
			var err error
			switch kind {
			case "password change":
				r.User.OldPassword = tests.TestPwd1
				r.User.Password = tests.TestPwd2
				err = db.ChangeUserPassword(r)
			case "password reset":
				r.User.Password = tests.TestPwd2
				err = db.ResetUserPassword(r)
			case "password update":
				r.User.Password = tests.TestPwd2
				err = db.UpdateUserPassword(r)
			case "mfa add":
				r.MfaToken = requests.MfaToken{Type: "totp", Comment: "test", Secret: "0123456789abcdef0123456789abcdef", Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
				err = db.AddMfaToken(r)
			case "mfa delete":
				err = db.DeleteMfaToken(r)
			case "disable enable":
				err = db.DisableUser(r)
				if err == nil {
					err = db.EnableUser(r)
				}
			case "challenge rules":
				r.User.Challenges = []string{"password", "totp"}
				err = db.OverwriteUserAuthChallengeRules(r)
			case "revoke":
				err = db.RevokeUserSessions(context.Background(), proof.UserID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := db.WithRefreshIdentity(context.Background(), proof, func(RefreshIdentity) error { t.Fatal("stale evidence reached issuer"); return nil }); !errors.Is(err, ErrRefreshIdentityDenied) {
				t.Fatal("security change accepted stale proof", err)
			}
			loaded, err := NewDatabase(db.GetPath())
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Users[0].CredentialVersion == 0 {
				t.Fatal("security version not persisted")
			}
		})
	}
}

func TestRefreshIdentitySerializesSecurityMutation(t *testing.T) {
	db, r := refreshTestDatabase(t)
	proof := r.Authentication
	entered, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	order := make(chan string, 2)
	go func() {
		defer wg.Done()
		err := db.WithRefreshIdentity(context.Background(), proof, func(RefreshIdentity) error { close(entered); <-release; order <- "issued"; return nil })
		if err != nil {
			t.Error(err)
		}
	}()
	<-entered
	go func() {
		defer wg.Done()
		if err := db.RevokeUserSessions(context.Background(), proof.UserID); err != nil {
			t.Error(err)
		}
		order <- "revoked"
	}()
	close(release)
	wg.Wait()
	if <-order != "issued" || <-order != "revoked" {
		t.Fatal("security change raced issuance")
	}
	if err := db.WithRefreshIdentity(context.Background(), proof, func(RefreshIdentity) error { return nil }); !errors.Is(err, ErrRefreshIdentityDenied) {
		t.Fatal("revoked proof usable")
	}
}

func TestAuthenticationEvidenceNeverSerialized(t *testing.T) {
	_, r := refreshTestDatabase(t)
	encoded, err := json.Marshal(r.Authentication)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{}" {
		t.Fatal("server-only evidence serialized")
	}
}
