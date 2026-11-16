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
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/bcrypt"
)

// GetCapabilities describes the password store without implying credential
// collections, factor ceremonies, or external-account attachment support.
func (s *Store) GetCapabilities() identity.StoreCapabilities {
	return identity.StoreCapabilities{
		ProfileRead: true, PasswordChange: true, Documents: true,
		AdminOperations: []string{"info", "add", "delete", "disable", "enable", "reset_password", "overwrite_roles", "add_roles"},
	}
}

// profileUser is a detached projection. It deliberately contains no password
// verifier, invented timestamps, or unsupported credential collections.
func profileUser(a accountRecord) *identity.User {
	u := &identity.User{ID: a.id, Username: a.account.Username, Disabled: !a.enabled, CredentialVersion: a.version,
		EmailAddress: &identity.EmailAddress{Address: a.account.Email}, Roles: make([]*identity.Role, 0, len(a.account.Roles))}
	if a.account.Name != "" {
		u.Name = &identity.Name{Last: a.account.Name, Alias: true}
	}
	for _, name := range a.account.Roles {
		// Preserve the complete stored role even when a slash component is empty.
		// Legacy clients join only nonempty organization/name fields.
		role := &identity.Role{Name: name}
		if organization, suffix, ok := strings.Cut(name, "/"); ok && organization != "" && suffix != "" {
			role.Organization, role.Name = organization, suffix
		}
		u.Roles = append(u.Roles, role)
	}
	return u
}

// RequestWithIdentity executes self-service against current immutable login
// evidence in the same immediate transaction as the read or password mutation.
// Trusted Request and management methods are intentionally separate APIs.
func (s *Store) RequestWithIdentity(op operator.Type, r *requests.Request) error {
	if r == nil {
		return identity.ErrIdentityRequestDenied
	}
	r.Response = requests.Response{}
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	proof := r.Authentication
	if proof.UserID == "" || proof.CredentialVersion == 0 || proof.BackendVersion != s.epoch ||
		r.User.Username == "" || r.User.Email == "" ||
		(r.Upstream.Realm != "" && r.Upstream.Realm != s.config.Realm) {
		return identity.ErrIdentityRequestDenied
	}
	ctx := context.Background()
	if r.Upstream.Request != nil {
		ctx = r.Upstream.Request.Context()
	}
	var result *identity.User
	err := s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		a, err := s.lookup(ctx, tx, proof.UserID, true)
		if errors.Is(err, ErrDenied) {
			return identity.ErrIdentityRequestDenied
		}
		if err != nil {
			return err
		}
		if !a.enabled || a.version != proof.CredentialVersion || a.account.Username != r.User.Username || a.account.Email != r.User.Email {
			return identity.ErrIdentityRequestDenied
		}
		if r.ValidateIdentity != nil {
			if err := r.ValidateIdentity(); err != nil {
				return err
			}
		}
		switch op {
		case operator.GetUser:
			result = profileUser(a)
			return nil
		case operator.ChangePassword:
			if identity.IsPasswordHashImport(r.User.Password) || r.User.OldPassword == "" || len(r.User.OldPassword) > 72 {
				return ErrInvalid
			}
			if cost, err := bcrypt.Cost([]byte(a.hash)); err != nil || cost != bcrypt.DefaultCost {
				// Match password authentication: an invalid stored verifier is a
				// storage fault, not evidence of an incorrect user-supplied password.
				return ErrUnavailable
			}
			if err := bcrypt.CompareHashAndPassword([]byte(a.hash), []byte(r.User.OldPassword)); err != nil {
				if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
					return ErrUnavailable
				}
				return ErrInvalid
			}
			hash, err := HashPassword(r.User.Password)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE accounts SET password=?,version=version+1 WHERE id=?", string(hash), a.id)
			return err
		default:
			return ErrUnsupported
		}
	})
	if err != nil {
		return err
	}
	// Neither results nor a success flag escape a failed/uncertain COMMIT.
	if result != nil {
		r.Response.Payload = result
	}
	r.Response.Code = 200
	return nil
}

var _ ids.IdentityRequestStore = (*Store)(nil)
var _ identity.StoreCapabilityProvider = (*Store)(nil)
