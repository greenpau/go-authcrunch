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
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// PutManifest installs encrypted metadata and the owner's wrapped key once.
func (s *Store) PutManifest(ctx context.Context, userID, id string, manifest Manifest) error {
	if _, err := decode(manifest.Metadata, 16, 32768); err != nil {
		return err
	}
	if err := manifest.Envelope.validate(); err != nil {
		return err
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		f, err := s.fileIn(ctx, tx, userID, id, true)
		if err != nil {
			return err
		}
		if f.Metadata != "" {
			if f.Metadata == manifest.Metadata && f.Envelope != nil && *f.Envelope == manifest.Envelope {
				return nil
			}
			return ErrConflict
		}
		if f.State != "uploading" {
			return ErrConflict
		}
		key, err := keyIn(ctx, tx, userID)
		if err != nil {
			return err
		}
		if key.KeyID != manifest.Envelope.KeyID {
			return ErrConflict
		}
		data, _ := json.Marshal(manifest.Envelope)
		if _, err := tx.ExecContext(ctx, `INSERT INTO shares VALUES(?,?,?)`, id, userID, string(data)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE files SET metadata=? WHERE id=?`, manifest.Metadata, id)
		return err
	})
}

// PutChunk persists one ciphertext chunk. Identical retries are safe before or
// after commit. Replacement fails, preventing nonce/key reuse in the client.
func (s *Store) PutChunk(ctx context.Context, userID, id string, number int, ciphertext []byte) error {
	if number < 0 || len(ciphertext) < 16 || len(ciphertext) > ChunkSize+16 {
		return ErrInvalid
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		f, err := s.fileIn(ctx, tx, userID, id, true)
		if err != nil {
			return err
		}
		if number >= f.Chunks {
			return ErrInvalid
		}
		want := int64(ChunkSize + 16)
		if number == f.Chunks-1 {
			want = f.Size - int64(f.Chunks-1)*(ChunkSize+16)
		}
		if int64(len(ciphertext)) != want {
			return ErrInvalid
		}
		var previous []byte
		err = tx.QueryRowContext(ctx, `SELECT ciphertext FROM chunks WHERE file=? AND number=?`, id, number).Scan(&previous)
		if err == nil {
			if bytes.Equal(previous, ciphertext) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if f.State != "uploading" {
			return ErrConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO chunks VALUES(?,?,?)`, id, number, ciphertext)
		return err
	})
}

// Commit publishes a complete upload atomically. No recipient can observe a
// partial file, and committing twice is harmless.
func (s *Store) Commit(ctx context.Context, userID, id string) error {
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		f, err := s.fileIn(ctx, tx, userID, id, true)
		if err != nil {
			return err
		}
		if f.State == "ready" {
			return nil
		}
		if f.Metadata == "" || f.Envelope == nil {
			return ErrConflict
		}
		var count int
		var size int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(ciphertext)),0) FROM chunks WHERE file=?`, id).Scan(&count, &size); err != nil {
			return err
		}
		if count != f.Chunks || size != f.Size {
			return ErrConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE files SET ready=1,expires=0 WHERE id=?`, id)
		return err
	})
}

// GetChunk authorizes within the same transaction that reads the ciphertext.
func (s *Store) GetChunk(ctx context.Context, userID, id string, number int) ([]byte, error) {
	var result []byte
	if number < 0 {
		return nil, ErrInvalid
	}
	err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		f, err := s.fileIn(ctx, tx, userID, id, false)
		if err != nil {
			return err
		}
		if f.State != "ready" || number >= f.Chunks {
			return ErrNotFound
		}
		err = tx.QueryRowContext(ctx, `SELECT ciphertext FROM chunks WHERE file=? AND number=?`, id, number).Scan(&result)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Share adds a read-only recipient to a committed document. Only the owner can
// share. Envelopes are immutable while a grant exists; revoke it before regrant.
func (s *Store) Share(ctx context.Context, userID, id, recipient string, envelope Envelope) error {
	if !ValidUserID(recipient) || recipient == userID || envelope.validate() != nil {
		return ErrInvalid
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		f, err := s.fileIn(ctx, tx, userID, id, true)
		if err != nil {
			return err
		}
		if f.State != "ready" {
			return ErrConflict
		}
		key, err := keyIn(ctx, tx, recipient)
		if err != nil {
			return err
		}
		if key.KeyID != envelope.KeyID {
			return ErrConflict
		}
		data, _ := json.Marshal(envelope)
		var previous string
		err = tx.QueryRowContext(ctx, `SELECT envelope FROM shares WHERE file=? AND recipient=?`, id, recipient).Scan(&previous)
		if err == nil {
			if previous == string(data) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM shares WHERE file=? AND recipient<>?`, id, userID).Scan(&count); err != nil {
			return err
		}
		if count >= s.config.MaxRecipients {
			return ErrQuota
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shares VALUES(?,?,?)`, id, recipient, string(data))
		return err
	})
}

// Recipients lists opaque grantee IDs for the owner, excluding the owner.
func (s *Store) Recipients(ctx context.Context, userID, id string) ([]string, error) {
	result := []string{}
	err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := s.fileIn(ctx, tx, userID, id, true); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT recipient FROM shares WHERE file=? AND recipient<>? ORDER BY recipient`, id, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var recipient string
			if err := rows.Scan(&recipient); err != nil {
				return err
			}
			result = append(result, recipient)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Revoke stops future API reads by a recipient. It cannot erase copies or keys
// already downloaded. Fresh content requires a new document and new content key.
func (s *Store) Revoke(ctx context.Context, userID, id, recipient string) error {
	if !ValidUserID(recipient) || userID == recipient {
		return ErrInvalid
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := s.fileIn(ctx, tx, userID, id, true); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM shares WHERE file=? AND recipient=?`, id, recipient)
		return err
	})
}

// Delete removes the owner's file, all chunks and all grants in one transaction.
func (s *Store) Delete(ctx context.Context, userID, id string) error {
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := s.fileIn(ctx, tx, userID, id, true); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM files WHERE id=?`, id)
		return err
	})
}
