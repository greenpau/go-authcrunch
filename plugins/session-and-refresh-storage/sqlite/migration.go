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
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

// Keep the old private byte format explicit. Adding Binding fields cannot make
// old records silently acquire managed authority or relax canonical decoding.
type bindingRecordV1 struct{ Portal, Origin, BasePath, Transport string }
type sessionRecordV1 struct {
	ID                               string
	ExternalIdentity                 *externalIdentityRecord `json:",omitempty"`
	Principal                        principalRecord
	Binding                          bindingRecordV1
	Current                          [32]byte
	Revision                         uint64
	IdleExpiresAt, AbsoluteExpiresAt int64
}

func decodeSessionV1(data []byte) (tokenrefresh.Session, error) {
	invalid := tokenrefresh.Session{}
	if len(data) == 0 || len(data) > 65536 {
		return invalid, tokenrefresh.ErrUnavailable
	}
	var record sessionRecordV1
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return invalid, tokenrefresh.ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid, tokenrefresh.ErrUnavailable
	}
	binding := tokenrefresh.Binding{Portal: record.Binding.Portal, Origin: record.Binding.Origin, BasePath: record.Binding.BasePath, Transport: record.Binding.Transport}
	s := tokenrefresh.Session{ID: record.ID, Principal: tokenrefresh.Principal(record.Principal), Binding: binding, Current: record.Current, Revision: record.Revision, IdleExpiresAt: record.IdleExpiresAt, AbsoluteExpiresAt: record.AbsoluteExpiresAt}
	s.Principal.ExternalIdentity = record.ExternalIdentity.proof()
	if !validSession(s) {
		return invalid, tokenrefresh.ErrUnavailable
	}
	// Reconstruct through the public values exactly as the old encoder did.
	// In particular, an explicit zero-valued external proof was never canonical.
	canonical := sessionRecordV1{
		ID: s.ID, ExternalIdentity: externalRecord(s.Principal.ExternalIdentity), Principal: principalRecord(s.Principal),
		Binding: bindingRecordV1{s.Binding.Portal, s.Binding.Origin, s.Binding.BasePath, s.Binding.Transport},
		Current: s.Current, Revision: s.Revision, IdleExpiresAt: s.IdleExpiresAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil || !bytes.Equal(data, encoded) {
		return invalid, tokenrefresh.ErrUnavailable
	}
	return s, nil
}

// migrateV1 is one transaction after exact old-schema and limit checks. It
// streams bounded records, preserves every spent digest, and removes the old
// SQL surface before committing the new version. Failures roll everything back.
func (s *Store) migrateV1(ctx context.Context, tx *sql.Tx) error {
	var families, digests int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM families").Scan(&families); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM digests").Scan(&digests); err != nil {
		return err
	}
	if families > int64(s.config.MaxSessions) || digests > int64(s.config.MaxSessions)*int64(s.config.MaxRotations+1) {
		return tokenrefresh.ErrUnavailable
	}
	if err := s.createSchema(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,payload,expires_at FROM families ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	var copied int64
	for rows.Next() {
		var id string
		var data []byte
		var expiry int64
		if err := rows.Scan(&id, &data, &expiry); err != nil {
			return err
		}
		session, err := decodeSessionV1(data)
		if err != nil || session.ID != id || session.IdleExpiresAt != expiry || session.Revision > uint64(s.config.MaxRotations) {
			return tokenrefresh.ErrUnavailable
		}
		encoded, err := encodeSession(session)
		if err != nil {
			return tokenrefresh.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO refresh_families_v2(id,namespace,generation,payload,expires_at) VALUES(?,'','',?,?)", id, encoded, expiry); err != nil {
			return err
		}
		n, err := copyV1Digests(ctx, tx, session)
		if err != nil {
			return err
		}
		copied += n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// Orphan digests must not disappear as a side effect of migration.
	if copied != digests {
		return tokenrefresh.ErrUnavailable
	}
	for _, statement := range []string{"DROP TABLE digests", "DROP TABLE families", "DROP TABLE settings", "PRAGMA user_version=2"} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return validateSchema(ctx, tx, schema[:])
}

func copyV1Digests(ctx context.Context, tx *sql.Tx, s tokenrefresh.Session) (int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT digest FROM digests WHERE family=?", s.ID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int64
	current := false
	for rows.Next() {
		var digest []byte
		if err := rows.Scan(&digest); err != nil {
			return 0, err
		}
		if len(digest) != 32 {
			return 0, tokenrefresh.ErrUnavailable
		}
		count++
		if uint64(count) > s.Revision+1 {
			return 0, tokenrefresh.ErrUnavailable
		}
		if bytes.Equal(digest, s.Current[:]) {
			current = true
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO refresh_digests_v2(digest,family) VALUES(?,?)", digest, s.ID); err != nil {
			return 0, err
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if !current || uint64(count) != s.Revision+1 {
		return 0, tokenrefresh.ErrUnavailable
	}
	return count, nil
}
