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
	stderrors "errors"
	"os"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// ErrRefreshIdentityDenied distinguishes revoked identities from store outages.
var ErrRefreshIdentityDenied = stderrors.New("refresh identity denied")

// RefreshIdentity contains fresh non-secret attributes of an immutable record.
type RefreshIdentity struct {
	Profile               *Profile `json:"-" xml:"-" yaml:"-"`
	Username, Email, Name string   `json:"-" xml:"-" yaml:"-"`
	Roles, Challenges     []string `json:"-" xml:"-" yaml:"-"`
}

func (db *Database) authenticationEvidence(u *User) requests.AuthenticationEvidence {
	return requests.AuthenticationEvidence{UserID: u.ID, CredentialVersion: u.CredentialVersion, BackendVersion: db.LoadedAt.Format(time.RFC3339Nano)}
}

// WithRefreshIdentity holds the database lock through issuance, so password
// changes, account disablement, MFA changes and logout-all cannot race a commit.
// Callbacks must not reenter the database. Reloading the database invalidates
// evidence even when a file was restored with an older security version.
func (db *Database) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(RefreshIdentity) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if db.inMemory {
		return db.withRefreshIdentityUnlocked(ctx, proof, apply)
	}
	return withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		if target.Revision != db.Revision {
			db.LoadedAt = time.Now().UTC()
		}
		target.LoadedAt = db.LoadedAt
		db.adoptMfaMutationSnapshot(target)
		return target.withRefreshIdentityUnlocked(ctx, proof, apply)
	})
}

func (db *Database) withRefreshIdentityUnlocked(ctx context.Context, proof requests.AuthenticationEvidence, apply func(RefreshIdentity) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := db.getUserByID(proof.UserID)
	if err != nil || u.Disabled || u.CredentialVersion != proof.CredentialVersion || proof.BackendVersion != db.LoadedAt.Format(time.RFC3339Nano) {
		return ErrRefreshIdentityDenied
	}
	if u.Lockout != nil && u.Lockout.IsLocked() {
		return ErrRefreshIdentityDenied
	}
	challenges, err := u.GetChallenges()
	if err != nil {
		return err
	}
	return apply(RefreshIdentity{Profile: u.Profile.Clone(), Username: u.Username, Email: u.GetMailClaim(), Name: u.GetNameClaim(), Roles: u.GetRolesClaim(), Challenges: append([]string(nil), challenges...)})
}

// RevokeUserSessions invalidates refresh families and pending login evidence for
// one immutable user ID. Already issued access JWTs retain their bounded life.
func (db *Database) RevokeUserSessions(ctx context.Context, userID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := db.refreshPersistedSnapshotUnlocked(); err != nil {
		return err
	}
	u, err := db.getUserByID(userID)
	if err != nil {
		return ErrRefreshIdentityDenied
	}
	u.CredentialVersion++
	return db.commit()
}
