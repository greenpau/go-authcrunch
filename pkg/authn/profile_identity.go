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

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

var errProfileIdentity = errors.New("profile identity requires a current identity-store login")

// profileIdentityStore keeps presentation claims and request payloads out of
// account selection. Each operation checks the captured proof in the backend's
// transaction, including operations performed after an initial profile check.
type profileIdentityStore struct {
	ids.IdentityStore
	bound            ids.IdentityRequestStore
	proof            requests.AuthenticationEvidence
	username, email  string
	validateIdentity func() error
}

func newProfileIdentityStore(backend ids.IdentityStore, usr *user.User) (*profileIdentityStore, error) {
	if backend == nil || usr == nil || usr.Authenticator.Method != backend.GetKind() ||
		usr.Authenticator.Name != backend.GetName() || usr.Authenticator.Realm != backend.GetRealm() ||
		usr.LoginUsername == "" || usr.LoginEmail == "" || usr.LoginEvidence.UserID == "" || usr.LoginEvidence.BackendVersion == "" {
		return nil, errProfileIdentity
	}
	bound, ok := backend.(ids.IdentityRequestStore)
	if !ok {
		return nil, errProfileIdentity
	}
	return &profileIdentityStore{IdentityStore: backend, bound: bound, proof: usr.LoginEvidence, username: usr.LoginUsername, email: usr.LoginEmail}, nil
}

func (s *profileIdentityStore) Request(op operator.Type, rr *requests.Request) error {
	rr.User.Username, rr.User.Email = s.username, s.email
	rr.Authentication = s.proof
	rr.ValidateIdentity = s.validateIdentity
	if rr.ValidateIdentity != nil {
		if err := rr.ValidateIdentity(); err != nil {
			return err
		}
	}
	return s.bound.RequestWithIdentity(op, rr)
}

// profileStoreCapabilities preserves the distinction between an older store
// with no capability declaration and an explicit declaration of no support.
// The identity adapter must not manufacture an optional provider interface.
func profileStoreCapabilities(backend ids.IdentityStore) (identity.StoreCapabilities, bool) {
	if bound, ok := backend.(*profileIdentityStore); ok {
		backend = bound.IdentityStore
	}
	if provider, ok := backend.(identity.StoreCapabilityProvider); ok {
		caps := provider.GetCapabilities()
		// An omitted Go slice still means no declared operations on the wire,
		// where clients expect an array rather than null.
		if caps.AdminOperations == nil {
			caps.AdminOperations = []string{}
		}
		return caps, true
	}
	return identity.StoreCapabilities{}, false
}
