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

package parser_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/password/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EPasswordHashConfiguration(t *testing.T) {
	c, err := parser.NewPasswordHashConfigFromDirectives([]string{"algorithm argon2", "memory 1024", "iterations 1", "parallelism 1"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := identity.NewPasswordWithConfig(tests.TestPwd1, "generic", c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	// Plaintext policy length must not constrain a valid encoded hash.
	db.Policy.Password.MaxLength = 72
	r := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: p.EncodedHash()}}
	if err := db.AddUser(r); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"reload", "update", "change", "reset"} {
		loaded, err := identity.NewDatabase(path)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Users[0].Passwords[0].Algorithm != "argon2" {
			t.Fatal("algorithm lost on reload")
		}
		for _, username := range []string{"alice", "ALICE", "alice@example.test", "ALICE@EXAMPLE.TEST"} {
			r.User.Username = username
			r.User.Password = tests.TestPwd1
			if loaded.AuthenticateUser(r) != nil || r.Authentication.UserID == "" {
				t.Fatal("persisted Argon2 login failed")
			}
		}
		r.User.Username = "alice"
		proof := r.Authentication
		r.User.OldPassword = tests.TestPwd1
		r.User.Password = p.EncodedHash()
		switch operation {
		case "update":
			err = loaded.UpdateUserPassword(r)
		case "change":
			err = loaded.ChangeUserPassword(r)
		case "reset":
			err = loaded.ResetUserPassword(r)
		}
		if err != nil {
			t.Fatal(err)
		}
		if operation != "reload" {
			err := loaded.WithRefreshIdentity(context.Background(), proof, func(identity.RefreshIdentity) error { t.Fatal("stale proof reached callback"); return nil })
			if !errors.Is(err, identity.ErrRefreshIdentityDenied) {
				t.Fatal("replacement preserved stale authentication evidence")
			}
		}
		r.User.Password = p.EncodedHash()
		if loaded.AuthenticateUser(r) == nil || r.Authentication.UserID != "" {
			t.Fatal("encoded hash authenticated as plaintext or retained proof")
		}
	}
}
