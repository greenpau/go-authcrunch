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

package documents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
)

// Store owns a private SQLite ciphertext database. Each operation is atomic
// across processes. Callers must authenticate and revalidate the supplied
// user ID, keeping identity revocation excluded through the operation.
type Store struct {
	db       *sqlitedb.Database
	config   Config
	portalID string
	now      func() time.Time
}

// Open binds a database permanently to a portal name, public origin and mount.
// Reusing it for a different portal fails closed. It never creates directories.
func Open(ctx context.Context, config Config, portalName string) (*Store, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !sqlitedb.ValidText(portalName, 128) {
		return nil, ErrConfig
	}
	schema := map[string]string{
		"identities": `CREATE TABLE identities (user_id TEXT PRIMARY KEY, source TEXT NOT NULL)`,
		"binding":    `CREATE TABLE binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), context TEXT NOT NULL, portal TEXT NOT NULL)`,
		"keys":       `CREATE TABLE keys (user_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, record TEXT NOT NULL)`,
		"files":      `CREATE TABLE files (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES keys(user_id), size INTEGER NOT NULL, chunks INTEGER NOT NULL, ready INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, expires INTEGER NOT NULL, metadata TEXT NOT NULL DEFAULT '', UNIQUE(owner,id))`,
		"chunks":     `CREATE TABLE chunks (file TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE, number INTEGER NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(file,number))`,
		"shares":     `CREATE TABLE shares (file TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE, recipient TEXT NOT NULL REFERENCES keys(user_id), envelope TEXT NOT NULL, PRIMARY KEY(file,recipient), UNIQUE(recipient,file))`,
	}
	db, err := sqlitedb.Open(ctx, config.Database, "5s", 0x41434442, schema)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, config: config, now: time.Now}
	binding, _ := json.Marshal([]string{Protocol, portalName, config.PublicOrigin, config.BasePath})
	err = db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var current string
		err := tx.QueryRowContext(ctx, `SELECT context,portal FROM binding WHERE singleton=1`).Scan(&current, &s.portalID)
		if errors.Is(err, sql.ErrNoRows) {
			s.portalID = randomID()
			_, err = tx.ExecContext(ctx, `INSERT INTO binding VALUES(1,?,?)`, string(binding), s.portalID)
			return err
		}
		if err != nil {
			return err
		}
		if current != string(binding) || !ValidID(s.portalID) {
			return ErrConfig
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// PortalID is persistent and independent of signing keys and process lifetimes.
func (s *Store) PortalID() string { return s.portalID }

// Close releases connections, preserving ciphertext and envelopes on disk.
// Hosts must drain requests before closing their portal.
func (s *Store) Close() error { return s.db.Close() }

// BindIdentity reserves an immutable local user ID for its authoritative store.
// Call it after transactional identity verification and before any operation.
// Bindings survive key reset: a colliding ID in a different store must never
// inherit the account's files or race a reset to claim ownership. MaxKeys also
// bounds these permanent reservations, including users without enrolled keys.
func (s *Store) BindIdentity(ctx context.Context, userID, backend, realm string) error {
	if !ValidUserID(userID) || !sqlitedb.ValidText(backend, 128) || !sqlitedb.ValidText(realm, 128) {
		return ErrInvalid
	}
	source, _ := json.Marshal([]string{backend, realm})
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var current string
		err := tx.QueryRowContext(ctx, `SELECT source FROM identities WHERE user_id=?`, userID).Scan(&current)
		if err == nil {
			if current != string(source) {
				return ErrIdentityConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM identities`).Scan(&count); err != nil {
			return err
		}
		if count >= s.config.MaxKeys {
			return ErrQuota
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO identities VALUES(?,?)`, userID, string(source))
		return err
	})
}

func keyIn(ctx context.Context, tx *sql.Tx, userID string) (Key, error) {
	var result Key
	var data string
	if !ValidUserID(userID) {
		return result, ErrInvalid
	}
	if err := tx.QueryRowContext(ctx, `SELECT record FROM keys WHERE user_id=?`, userID).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, ErrNotFound
		}
		return result, err
	}
	if json.Unmarshal([]byte(data), &result) != nil || result.validate(userID) != nil {
		return Key{}, sqlitedb.ErrUnavailable
	}
	return result, nil
}

// RegisterKey creates the caller's immutable key. An identical retry succeeds;
// replacement is rejected so old documents and saved fingerprints remain valid.
func (s *Store) RegisterKey(ctx context.Context, userID string, key Key) error {
	if err := key.validate(userID); err != nil {
		return err
	}
	data, _ := json.Marshal(key)
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		old, err := keyIn(ctx, tx, userID)
		if err == nil {
			previous, _ := json.Marshal(old)
			if string(previous) != string(data) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keys`).Scan(&count); err != nil {
			return err
		}
		if count >= s.config.MaxKeys {
			return ErrQuota
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO keys VALUES(?,?,?)`, userID, key.KeyID, string(data))
		return err
	})
}

// GetKey returns a public key, including its encrypted vault only to its owner.
// Exact local database user IDs are required; there is no account enumeration API.
func (s *Store) GetKey(ctx context.Context, requester, userID string) (Key, error) {
	var result Key
	if !ValidUserID(requester) {
		return result, ErrInvalid
	}
	err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		result, err = keyIn(ctx, tx, userID)
		return err
	})
	if err != nil {
		return Key{}, err
	}
	if requester != userID {
		result.Vault = nil
	}
	return result, nil
}

// ResetKey permanently removes the caller's owned documents, received grants
// and key registration in one transaction. It enables a fresh enrollment after
// key loss; it does not recover old plaintext. Clients must make that consequence
// explicit before invoking this operation. Other users' owned files survive.
// expectedKeyID binds confirmation and retries to the registration shown to the
// user; a stale reset must not delete a newly enrolled replacement key.
func (s *Store) ResetKey(ctx context.Context, userID, expectedKeyID string) error {
	if !ValidUserID(userID) || !ValidID(expectedKeyID) {
		return ErrInvalid
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		key, err := keyIn(ctx, tx, userID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if key.KeyID != expectedKeyID {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE owner=?`, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM shares WHERE recipient=?`, userID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM keys WHERE user_id=?`, userID)
		return err
	})
}

func (s *Store) prune(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM files WHERE ready=0 AND expires<=?`, s.now().Unix())
	return err
}

// Allocate reserves the entire encrypted size and creates a random, immutable
// file ID before the client encrypts anything. Expired unfinished uploads are
// collected during allocation; they cannot be read or resumed after expiration.
func (s *Store) Allocate(ctx context.Context, userID string, size int64, chunks int) (File, error) {
	if !ValidUserID(userID) || size < 16 || size > s.config.MaxFileBytes || chunks < 1 || chunks > 4096 || size <= int64(chunks-1)*(ChunkSize+16) || size > int64(chunks)*(ChunkSize+16) || size-int64(chunks-1)*(ChunkSize+16) < 16 || (chunks > 1 && size-int64(chunks-1)*(ChunkSize+16) == 16) {
		return File{}, ErrInvalid
	}
	var result File
	err := s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := keyIn(ctx, tx, userID); err != nil {
			return err
		}
		if err := s.prune(ctx, tx); err != nil {
			return err
		}
		var userBytes, totalBytes int64
		var count, totalCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(size),0) FROM files WHERE owner=?`, userID).Scan(&count, &userBytes); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(size),0) FROM files`).Scan(&totalCount, &totalBytes); err != nil {
			return err
		}
		if count >= s.config.MaxUserFiles || totalCount >= s.config.MaxTotalFiles || userBytes+size > s.config.MaxUserBytes || totalBytes+size > s.config.MaxTotalBytes {
			return ErrQuota
		}
		result = File{ID: randomID(), Owner: userID, Size: size, Chunks: chunks, State: "uploading", CreatedAt: s.now().Unix(), ExpiresAt: s.now().Unix() + s.config.UploadTTLSeconds}
		_, err := tx.ExecContext(ctx, `INSERT INTO files(id,owner,size,chunks,created,expires) VALUES(?,?,?,?,?,?)`, result.ID, userID, size, chunks, result.CreatedAt, result.ExpiresAt)
		return err
	})
	if err != nil {
		return File{}, err
	}
	return result, nil
}

func (s *Store) fileIn(ctx context.Context, tx *sql.Tx, userID, id string, ownerOnly bool) (File, error) {
	var f File
	var ready int
	if !ValidUserID(userID) || !ValidID(id) {
		return f, ErrInvalid
	}
	err := tx.QueryRowContext(ctx, `SELECT id,owner,size,chunks,ready,created,expires,metadata FROM files WHERE id=?`, id).Scan(&f.ID, &f.Owner, &f.Size, &f.Chunks, &ready, &f.CreatedAt, &f.ExpiresAt, &f.Metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	if err != nil {
		return File{}, err
	}
	if ready == 0 && (f.ExpiresAt <= s.now().Unix() || f.Owner != userID) {
		return File{}, ErrNotFound
	}
	f.State = "uploading"
	if ready == 1 {
		f.State = "ready"
		f.ExpiresAt = 0
	}
	if ownerOnly && f.Owner != userID {
		return File{}, ErrNotFound
	}
	var envelope string
	err = tx.QueryRowContext(ctx, `SELECT envelope FROM shares WHERE file=? AND recipient=?`, id, userID).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) {
		if f.Owner != userID {
			return File{}, ErrNotFound
		}
		return f, nil
	}
	if err != nil {
		return File{}, err
	}
	var e Envelope
	if json.Unmarshal([]byte(envelope), &e) != nil || e.validate() != nil {
		return File{}, sqlitedb.ErrUnavailable
	}
	f.Envelope = &e
	return f, nil
}

// GetFile returns a descriptor and only the requesting recipient's envelope.
func (s *Store) GetFile(ctx context.Context, userID, id string) (File, error) {
	var result File
	err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		result, err = s.fileIn(ctx, tx, userID, id, false)
		return err
	})
	if err != nil {
		return File{}, err
	}
	return result, nil
}

// ListFiles returns at most 100 accessible descriptors, in identifier order.
func (s *Store) ListFiles(ctx context.Context, userID, after string) (Page, error) {
	result := Page{Files: []File{}}
	if !ValidUserID(userID) || (after != "" && !ValidID(after)) {
		return Page{}, ErrInvalid
	}
	err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT f.id,f.owner,f.size,f.chunks,f.ready,f.created,f.expires FROM files f WHERE f.id>? AND ((f.owner=? AND (f.ready=1 OR f.expires>?)) OR (f.ready=1 AND EXISTS(SELECT 1 FROM shares s WHERE s.file=f.id AND s.recipient=?))) ORDER BY f.id LIMIT 101`, after, userID, s.now().Unix(), userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f File
			var ready int
			if err := rows.Scan(&f.ID, &f.Owner, &f.Size, &f.Chunks, &ready, &f.CreatedAt, &f.ExpiresAt); err != nil {
				return err
			}
			f.State = "uploading"
			if ready == 1 {
				f.State = "ready"
				f.ExpiresAt = 0
			}
			result.Files = append(result.Files, f)
		}
		return rows.Err()
	})
	if err != nil {
		return Page{}, err
	}
	if len(result.Files) > 100 {
		result.Files = result.Files[:100]
		result.Next = result.Files[99].ID
	}
	return result, nil
}
