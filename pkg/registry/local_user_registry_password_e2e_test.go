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

package registry

import (
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2ELocalUserRegistryRejectsPasswordHashImports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registrations.json")
	configured := &LocalUserRegistryProvider{
		Name: "registration", Dropbox: path, EmailProviderName: "unused",
		AdminEmails: []string{"admin@example.test"}, IdentityStoreName: "local", RealmName: "local",
	}
	registry, err := configured.NewRuntime(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)

	for i, candidate := range []string{
		tests.TestPwd2Hash(t),
		"bcrypt:malformed",
		"argon2:$argon2id$v=19$m=8,t=1,p=1$MDEyMzQ1Njc$MDEyMzQ1Njc4OWFiY2RlZg",
		" \targon2:malformed\n",
	} {
		r := &requests.Request{User: requests.User{
			Username: "alice", Email: "alice@example.test", Password: candidate, Roles: []string{"authp/user"},
		}}
		if err := registry.AddUser(r); err == nil {
			t.Errorf("registration password hash import case %d was accepted", i)
		} else if strings.Contains(err.Error(), candidate) {
			t.Fatal("registration error disclosed the submitted credential")
		}
		persisted, err := identity.NewDatabase(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(persisted.Users) != 0 {
			t.Fatal("rejected registration persisted an identity")
		}
	}

	plain := &requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"},
	}}
	if err := registry.AddUser(plain); err != nil {
		t.Fatal("ordinary plaintext registration failed", err)
	}
	persisted, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	login := &requests.Request{User: requests.User{Username: "alice", Password: tests.TestPwd1}}
	if err := persisted.AuthenticateUser(login); err != nil {
		t.Fatal("persisted plaintext registration could not authenticate", err)
	}
}
