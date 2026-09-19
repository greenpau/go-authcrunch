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

package authn

import (
	"errors"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type profileIdentityTestStore struct {
	ids.IdentityStore
	got    *requests.Request
	denied bool
}

func (*profileIdentityTestStore) GetName() string  { return "database" }
func (*profileIdentityTestStore) GetRealm() string { return "local" }
func (s *profileIdentityTestStore) RequestWithIdentity(_ operator.Type, rr *requests.Request) error {
	snapshot := *rr
	s.got = &snapshot
	if s.denied {
		return errProfileIdentity
	}
	return nil
}

func TestProfileIdentityUsesServerProofOnEveryOperation(t *testing.T) {
	store := &profileIdentityTestStore{}
	proof := requests.AuthenticationEvidence{UserID: "immutable-alice", BackendVersion: "reload-epoch", CredentialVersion: 7}
	usr, err := user.NewUser(map[string]any{"sub": "bob", "email": "bob@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	usr.Authenticator = user.Authenticator{Name: "database", Realm: "local", Method: "local"}
	usr.LoginEvidence, usr.LoginUsername, usr.LoginEmail = proof, "alice", "alice@example.test"
	bound, err := newProfileIdentityStore(store, usr)
	if err != nil {
		t.Fatal(err)
	}
	// The adapter holds its own identity snapshot; later mutable user/request
	// fields cannot redirect an operation to another account or upgrade proof.
	usr.LoginUsername, usr.LoginEvidence.UserID = "bob", "immutable-bob"
	for _, op := range []operator.Type{operator.GetUser, operator.AddAPIKey, operator.DeleteMfaToken, operator.OverwriteAuthChallengeRules} {
		rr := &requests.Request{User: requests.User{Username: "bob", Email: "bob@example.test"}}
		if err := bound.Request(op, rr); err != nil {
			t.Fatal(err)
		}
		if store.got.User.Username != "alice" || store.got.User.Email != "alice@example.test" || store.got.Authentication != proof {
			t.Fatal("profile operation did not retain its original authenticated identity")
		}
	}
	store.denied = true
	if err := bound.Request(operator.AddAPIKey, requests.NewRequest()); !errors.Is(err, errProfileIdentity) {
		t.Fatal("backend revocation was not propagated")
	}
}

func TestProfileIdentityRejectsIncompleteOrMismatchedBinding(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*user.User)
	}{
		{"missing username", func(u *user.User) { u.LoginUsername = "" }},
		{"missing email", func(u *user.User) { u.LoginEmail = "" }},
		{"missing immutable ID", func(u *user.User) { u.LoginEvidence.UserID = "" }},
		{"missing backend epoch", func(u *user.User) { u.LoginEvidence.BackendVersion = "" }},
		{"different realm", func(u *user.User) { u.Authenticator.Realm = "other" }},
		{"different backend", func(u *user.User) { u.Authenticator.Name = "other" }},
		{"external login", func(u *user.User) { u.Authenticator.Method = "oauth2" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			u := &user.User{Authenticator: user.Authenticator{Name: "database", Realm: "local", Method: "local"}, LoginUsername: "alice", LoginEmail: "alice@example.test", LoginEvidence: requests.AuthenticationEvidence{UserID: "alice-id", BackendVersion: "epoch"}}
			change.apply(u)
			if bound, err := newProfileIdentityStore(&profileIdentityTestStore{}, u); err == nil || bound != nil {
				t.Fatal("incomplete or mismatched identity accepted")
			}
		})
	}
	if _, err := newProfileIdentityStore(nil, nil); err == nil {
		t.Fatal("nil identity accepted")
	}
}
