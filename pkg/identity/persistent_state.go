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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

type persistentIdentityEpoch struct {
	Digest   [32]byte
	LoadedAt time.Time
}

// ConfigurePersistentState preserves the backend epoch only when the exact
// identity file matches the last durable snapshot. Replaced/rolled-back files
// invalidate old proofs. Ordinary credential-version checks remain mandatory.
// Configure before exposing this database; the caller owns store.
func (db *Database) ConfigurePersistentState(store *state.Store) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if store == nil || db.state != nil || db.inMemory {
		return fmt.Errorf("identity persistence requires an unused file-backed database")
	}
	canonical, err := canonicalDatabasePath(db.path)
	if err != nil {
		return err
	}
	record, err := store.OpenRecord("identity-epoch/"+canonical, "identity-epoch-v1")
	if err != nil {
		return err
	}
	return withDatabaseFileLock(db.path, func() error {
		raw, err := os.ReadFile(db.path)
		if err != nil {
			return err
		}
		current, err := db.newIdentityRequestTarget(raw)
		if err != nil {
			return err
		}
		var previous persistentIdentityEpoch
		found, err := record.Decode(&previous)
		if err != nil {
			return err
		}
		if found && previous.Digest == sha256.Sum256(raw) && !previous.LoadedAt.IsZero() {
			current.LoadedAt = previous.LoadedAt
		} else if !found {
			loadedSnapshot, marshalErr := json.Marshal(db)
			if marshalErr != nil {
				return marshalErr
			}
			currentSnapshot, marshalErr := json.Marshal(current)
			if marshalErr != nil {
				return marshalErr
			}
			if !bytes.Equal(loadedSnapshot, currentSnapshot) {
				current.LoadedAt = time.Now().UTC()
			}
		} else {
			current.LoadedAt = time.Now().UTC()
		}
		db.adoptMfaMutationSnapshot(current)
		db.LoadedAt = current.LoadedAt
		db.state = record
		return db.persistEpoch()
	})
}

// Called under the database/file transaction, after writing a new file or
// before issuing authority based on current identity. No raw identity data is
// copied to runtime storage, only its digest and proof epoch.
func (db *Database) persistEpoch() error {
	if db.state == nil {
		return nil
	}
	raw, err := os.ReadFile(db.path)
	if err != nil {
		return err
	}
	return db.state.Encode(persistentIdentityEpoch{Digest: sha256.Sum256(raw), LoadedAt: db.LoadedAt})
}
