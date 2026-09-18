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
	stderrors "errors"
	"os"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// ErrIdentityRequestDenied reports profile access whose authentication
// evidence no longer identifies the current enabled and unlocked account.
var ErrIdentityRequestDenied = stderrors.New("identity request denied")

// RequestWithIdentity executes an explicitly supported self-service operation
// against the immutable identity and security version in the request.
func (db *Database) RequestWithIdentity(op operator.Type, r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if r == nil {
		return ErrIdentityRequestDenied
	}
	if db.inMemory {
		return db.requestWithIdentityUnlocked(op, r, nil)
	}
	return withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		return db.requestWithIdentityUnlocked(op, r, data)
	})
}

func (db *Database) requestWithIdentityUnlocked(op operator.Type, r *requests.Request, persisted []byte) error {
	target, err := db.newIdentityRequestTarget(persisted)
	if err != nil {
		return err
	}
	user, identityErr := target.validateUserIdentity(r.User.Username, r.User.Email)
	proof := r.Authentication
	if identityErr != nil || proof.UserID == "" || proof.BackendVersion == "" || user.Disabled ||
		user.ID != proof.UserID || user.CredentialVersion != proof.CredentialVersion ||
		proof.BackendVersion != db.LoadedAt.Format(time.RFC3339Nano) ||
		user.Lockout != nil && user.Lockout.IsLocked() {
		if persisted != nil && target.Revision != db.Revision {
			db.adoptMfaMutationSnapshot(target)
			db.LoadedAt = time.Now().UTC()
		}
		return ErrIdentityRequestDenied
	}

	initialRevision := target.Revision
	if err := requestIdentityOperation(target, op, r); err != nil {
		return err
	}
	if persisted != nil && target.Revision != initialRevision {
		target.inMemory = false
		if err := target.writeSnapshotUnlocked(); err != nil {
			return err
		}
	}
	live, err := db.cloneIdentityRequestTarget(target)
	if err != nil {
		return err
	}
	db.adoptMfaMutationSnapshot(live)
	return nil
}

func (db *Database) newIdentityRequestTarget(persisted []byte) (*Database, error) {
	if persisted == nil {
		var err error
		persisted, err = json.Marshal(db)
		if err != nil {
			return nil, errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
	}
	target := &Database{
		mu:       &sync.RWMutex{},
		path:     db.path,
		inMemory: true,
		LoadedAt: db.LoadedAt,
	}
	if err := json.Unmarshal(persisted, target); err != nil {
		return nil, errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if err := target.indexMfaMutationSnapshot(); err != nil {
		return nil, errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	target.LoadedAt = db.LoadedAt
	return target, nil
}

func (db *Database) cloneIdentityRequestTarget(target *Database) (*Database, error) {
	data, err := json.Marshal(target)
	if err != nil {
		return nil, errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	clone := &Database{path: db.path}
	if err := json.Unmarshal(data, clone); err != nil {
		return nil, errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if err := clone.indexMfaMutationSnapshot(); err != nil {
		return nil, errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	clone.LoadedAt = db.LoadedAt
	return clone, nil
}

func requestIdentityOperation(db *Database, op operator.Type, r *requests.Request) error {
	switch op {
	case operator.ChangePassword:
		return db.ChangeUserPassword(r)
	case operator.GetPublicKeys:
		return db.GetPublicKeys(r)
	case operator.GetPublicKey:
		return db.GetPublicKey(r)
	case operator.GetAPIKeys:
		return db.GetAPIKeys(r)
	case operator.GetAPIKey:
		return db.GetAPIKey(r)
	case operator.AddKeySSH, operator.AddKeyGPG:
		return db.AddPublicKey(r)
	case operator.DeletePublicKey:
		return db.DeletePublicKey(r)
	case operator.AddMfaToken:
		return db.AddMfaToken(r)
	case operator.DeleteMfaToken:
		return db.DeleteMfaToken(r)
	case operator.AddAPIKey:
		return db.AddAPIKey(r)
	case operator.DeleteAPIKey:
		return db.DeleteAPIKey(r)
	case operator.GetMfaTokens:
		return db.GetMfaTokens(r)
	case operator.GetMfaToken:
		return db.GetMfaToken(r)
	case operator.GetUser:
		return db.GetUser(r)
	case operator.OverwriteAuthChallengeRules:
		return db.OverwriteUserAuthChallengeRules(r)
	default:
		return ErrIdentityRequestDenied
	}
}
