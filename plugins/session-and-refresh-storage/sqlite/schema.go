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

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

const applicationID = 1094931014
const schemaVersion = 2

// New names are deliberate: an already-open old reader must not be able to
// mutate new families with the old SQL after migration, even before reopening.
var schema = [...]struct{ name, sql string }{
	{"refresh_settings_v2", "CREATE TABLE refresh_settings_v2 (id INTEGER PRIMARY KEY CHECK(id=1), max_sessions INTEGER NOT NULL CHECK(max_sessions BETWEEN 1 AND 100000), max_rotations INTEGER NOT NULL CHECK(max_rotations BETWEEN 1 AND 100000))"},
	{"refresh_generations_v2", "CREATE TABLE refresh_generations_v2 (namespace TEXT PRIMARY KEY NOT NULL CHECK(length(namespace)=64 AND namespace NOT GLOB '*[^0-9a-f]*'), generation TEXT NOT NULL CHECK(length(generation)=64 AND generation NOT GLOB '*[^0-9a-f]*'))"},
	{"refresh_families_v2", "CREATE TABLE refresh_families_v2 (id TEXT PRIMARY KEY NOT NULL, namespace TEXT NOT NULL, generation TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=65536), expires_at INTEGER NOT NULL, CHECK((namespace='' AND generation='') OR (length(namespace)=64 AND namespace NOT GLOB '*[^0-9a-f]*' AND length(generation)=64 AND generation NOT GLOB '*[^0-9a-f]*')))"},
	{"refresh_families_expiry_v2", "CREATE INDEX refresh_families_expiry_v2 ON refresh_families_v2(expires_at)"},
	{"refresh_families_generation_v2", "CREATE INDEX refresh_families_generation_v2 ON refresh_families_v2(namespace,generation)"},
	{"refresh_digests_v2", "CREATE TABLE refresh_digests_v2 (digest BLOB PRIMARY KEY NOT NULL CHECK(length(digest)=32), family TEXT NOT NULL REFERENCES refresh_families_v2(id) ON DELETE CASCADE)"},
	{"refresh_digests_family_v2", "CREATE INDEX refresh_digests_family_v2 ON refresh_digests_v2(family)"},
}

var schemaV1 = [...]struct{ name, sql string }{
	{"settings", "CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), max_sessions INTEGER NOT NULL, max_rotations INTEGER NOT NULL)"},
	{"families", "CREATE TABLE families (id TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=65536), expires_at INTEGER NOT NULL)"},
	{"families_expiry", "CREATE INDEX families_expiry ON families(expires_at)"},
	{"digests", "CREATE TABLE digests (digest BLOB PRIMARY KEY NOT NULL CHECK(length(digest)=32), family TEXT NOT NULL REFERENCES families(id) ON DELETE CASCADE)"},
	{"digests_family", "CREATE INDEX digests_family ON digests(family)"},
}

// sqlReader admits only read operations, so readiness cannot accidentally enter
// the write/COMMIT helper. The same exact-schema check serves initialization.
type sqlReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validateSchema(ctx context.Context, reader sqlReader, expected []struct{ name, sql string }) error {
	rows, err := reader.QueryContext(ctx, "SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'")
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			return err
		}
		found := false
		for _, object := range expected {
			if object.name == name && object.sql == definition {
				found = true
				break
			}
		}
		if !found {
			return tokenrefresh.ErrUnavailable
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(expected) {
		return tokenrefresh.ErrUnavailable
	}
	return nil
}

func (s *Store) validateLimits(ctx context.Context, reader sqlReader, table string) error {
	// Callers choose one of the two fixed private schema identifiers.
	var sessions, rotations int
	if err := reader.QueryRowContext(ctx, "SELECT max_sessions,max_rotations FROM "+table+" WHERE id=1").Scan(&sessions, &rotations); err != nil {
		return err
	}
	if sessions != s.config.MaxSessions || rotations != s.config.MaxRotations {
		return tokenrefresh.ErrUnavailable
	}
	return nil
}

func (s *Store) createSchema(ctx context.Context, tx *sql.Tx) error {
	for _, object := range schema {
		if _, err := tx.ExecContext(ctx, object.sql); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO refresh_settings_v2 VALUES(1,?,?)", s.config.MaxSessions, s.config.MaxRotations)
	return err
}

func (s *Store) initialize(ctx context.Context, tx *sql.Tx) error {
	var journal string
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "delete" {
		return tokenrefresh.ErrUnavailable
	}
	var app, version int
	if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if app == 0 && version == 0 {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return tokenrefresh.ErrUnavailable
		}
		if err := s.createSchema(ctx, tx); err != nil {
			return err
		}
		for _, statement := range []string{"PRAGMA application_id=1094931014", "PRAGMA user_version=2"} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}
	if app != applicationID {
		return tokenrefresh.ErrUnavailable
	}
	switch version {
	case 1:
		if err := validateSchema(ctx, tx, schemaV1[:]); err != nil {
			return err
		}
		// Limits must match before even tentative migration DDL is issued.
		if err := s.validateLimits(ctx, tx, "settings"); err != nil {
			return err
		}
		return s.migrateV1(ctx, tx)
	case schemaVersion:
		if err := validateSchema(ctx, tx, schema[:]); err != nil {
			return err
		}
		return s.validateLimits(ctx, tx, "refresh_settings_v2")
	default:
		return tokenrefresh.ErrUnavailable
	}
}
