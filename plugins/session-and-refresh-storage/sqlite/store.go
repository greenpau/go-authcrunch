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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	driver "modernc.org/sqlite"
)

// Store implements atomic refresh storage shared by clients on one local host.
// Use a dedicated database in a trusted private directory, on a filesystem with
// reliable SQLite locking and sync. The host owns Close and identity consistency.
// Records contain private authentication evidence but no raw refresh tokens;
// this plugin does not encrypt the database or distribute other portal caches.
type Store struct {
	db      *sql.DB
	config  Config
	file    os.FileInfo
	timeout time.Duration
	closed  atomic.Bool
	now     func() time.Time
}

var (
	_ tokenrefresh.ReplacementStore = (*Store)(nil)
	_ tokenrefresh.SessionValidator = (*Store)(nil)
)

// ErrCommitUncertain means a commit was attempted but credentials must not be
// published. The token may be spent. Do not retry the exchange; require fresh
// authentication. Database commit or file-health failures also disable the
// affected handle; request cancellation or expiry alone leaves it usable.
var ErrCommitUncertain = errors.New("SQLite refresh commit outcome is uncertain")

// New opens or initializes a dedicated database, snapshotting validated config.
// Existing databases must have this plugin's schema and identical limits. Failed
// construction returns no runtime. A newly created empty file may remain.
func New(ctx context.Context, config *Config) (*Store, error) {
	if ctx == nil || config == nil {
		return nil, tokenrefresh.ErrUnavailable
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Permission bits cannot establish this storage contract on Windows.
	if runtime.GOOS == "windows" {
		return nil, tokenrefresh.ErrUnavailable
	}
	info, err := prepareFile(c.Path)
	if err != nil {
		return nil, tokenrefresh.ErrUnavailable
	}
	values := url.Values{
		"mode":    {"rw"},
		"_txlock": {"immediate"},
		"_pragma": {"busy_timeout(0)", "foreign_keys(1)", "synchronous(EXTRA)", "fullfsync(1)", "secure_delete(1)"},
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(c.Path), RawQuery: values.Encode()}
	connector, err := driver.NewConnector(uri.String())
	if err != nil {
		return nil, tokenrefresh.ErrUnavailable
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	timeout, _ := time.ParseDuration(c.Timeout)
	s := &Store{db: db, config: c, file: info, timeout: timeout, now: time.Now}
	if err := s.transact(ctx, nil, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		return true, s.initialize(ctx, tx)
	}); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func prepareFile(path string) (os.FileInfo, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, tokenrefresh.ErrUnavailable
	}
	_, err = os.Lstat(path)
	if os.IsNotExist(err) {
		// Close the creation descriptor before publishing the canonical name.
		// On POSIX, closing any descriptor for an inode can release another
		// SQLite connection's process-wide locks, even in a different goroutine.
		f, err := os.CreateTemp(filepath.Dir(path), ".authcrunch-sqlite-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil || closeErr != nil {
			return nil, tokenrefresh.ErrUnavailable
		}
		// Link publishes without replacing a concurrent constructor's database.
		// Do not use Rename: an existing, active destination must survive.
		if err := os.Link(f.Name(), path); err != nil && !os.IsExist(err) {
			return nil, err
		}
		if err := os.Remove(f.Name()); err != nil {
			return nil, err
		}
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		syncErr = directory.Sync()
		closeErr = directory.Close()
		if syncErr != nil || closeErr != nil {
			return nil, tokenrefresh.ErrUnavailable
		}
	} else if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, tokenrefresh.ErrUnavailable
	}
	return info, nil
}

// healthy rejects removed/replaced files instead of silently reconnecting to a
// different database, and refuses unsafe journal files before SQLite opens them.
func (s *Store) healthy() bool {
	parent, err := os.Lstat(filepath.Dir(s.config.Path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return false
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		info, err := os.Lstat(s.config.Path + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return false
		}
		if suffix == "" && !os.SameFile(s.file, info) {
			return false
		}
	}
	return true
}

var schema = [...]struct{ name, sql string }{
	{"settings", "CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), max_sessions INTEGER NOT NULL, max_rotations INTEGER NOT NULL)"},
	{"families", "CREATE TABLE families (id TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=65536), expires_at INTEGER NOT NULL)"},
	{"families_expiry", "CREATE INDEX families_expiry ON families(expires_at)"},
	{"digests", "CREATE TABLE digests (digest BLOB PRIMARY KEY NOT NULL CHECK(length(digest)=32), family TEXT NOT NULL REFERENCES families(id) ON DELETE CASCADE)"},
	{"digests_family", "CREATE INDEX digests_family ON digests(family)"},
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
	// GLOB treats the underscore in SQLite's reserved prefix literally. LIKE
	// would also hide unrelated tables such as sqliteX_foreign.
	if app == 0 && version == 0 {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return tokenrefresh.ErrUnavailable
		}
		for _, statement := range []string{"PRAGMA application_id = 1094931014", "PRAGMA user_version = 1"} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		for _, object := range schema {
			if _, err := tx.ExecContext(ctx, object.sql); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO settings VALUES(1, ?, ?)", s.config.MaxSessions, s.config.MaxRotations)
		return err
	}
	if app != 1094931014 || version != 1 {
		return tokenrefresh.ErrUnavailable
	}
	var capacity, rotations int
	if err := tx.QueryRowContext(ctx, "SELECT max_sessions, max_rotations FROM settings WHERE id=1").Scan(&capacity, &rotations); err != nil {
		return err
	}
	if capacity != s.config.MaxSessions || rotations != s.config.MaxRotations {
		return tokenrefresh.ErrUnavailable
	}
	// Schema version 1 has exact definitions: changed constraints, triggers or
	// missing indexes must fail construction, before any runtime is published.
	rows, err := tx.QueryContext(ctx, "SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'")
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
		for _, object := range schema {
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
	if count != len(schema) {
		return tokenrefresh.ErrUnavailable
	}
	return nil
}

// transact retries only lock acquisition before any work. After BEGIN IMMEDIATE,
// all decisions use current state. Semantic replay/expiry failures can commit a
// family deletion; ordinary failures roll back. A commit is never retried.
func (s *Store) transact(ctx context.Context, beforeCommit func() error, action func(context.Context, *sql.Tx) (bool, error)) error {
	if s == nil || s.db == nil || ctx == nil || s.closed.Load() {
		return tokenrefresh.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.healthy() {
		return tokenrefresh.ErrUnavailable
	}
	var tx *sql.Tx
	for {
		var err error
		tx, err = s.db.BeginTx(ctx, nil)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var failure *driver.Error
		if !errors.As(err, &failure) || failure.Code()&255 != 5 {
			return tokenrefresh.ErrUnavailable
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer tx.Rollback()
	commit, err := action(ctx, tx)
	if !commit {
		return safeError(ctx, err)
	}
	// SQL failures always roll back, even if the action intended to commit.
	if err != nil && !errors.Is(err, tokenrefresh.ErrInvalid) {
		return safeError(ctx, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.closed.Load() || !s.healthy() {
		return tokenrefresh.ErrUnavailable
	}
	if err == nil && beforeCommit != nil {
		if check := beforeCommit(); check != nil {
			return check
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		// database/sql can reject Commit before calling the driver when this
		// transaction's context is canceled (including automatic rollback).
		// The SQLite driver's Commit uses a background context, so these errors
		// cannot represent an uncertain database commit. Rollback is retry-safe.
		if ctx.Err() != nil && (errors.Is(commitErr, context.Canceled) || errors.Is(commitErr, context.DeadlineExceeded) || errors.Is(commitErr, sql.ErrTxDone)) {
			return ctx.Err()
		}
		// Disable this handle after an uncertain commit. Reopen only after the
		// host has reconciled the failed operation; never publish credentials.
		s.closed.Store(true)
		return ErrCommitUncertain
	}
	if ctx.Err() != nil {
		// SQLite committed successfully. Withhold this request's credentials,
		// but its cancellation says nothing about other families' storage health.
		return errors.Join(ErrCommitUncertain, ctx.Err())
	}
	if s.closed.Load() || !s.healthy() {
		s.closed.Store(true)
		return ErrCommitUncertain
	}
	if err == nil && beforeCommit != nil {
		if check := beforeCommit(); check != nil {
			return ErrCommitUncertain
		}
	}
	return err
}

func safeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil || errors.Is(err, tokenrefresh.ErrInvalid) || errors.Is(err, tokenrefresh.ErrUnavailable) {
		return err
	}
	return tokenrefresh.ErrUnavailable
}

// Close rejects new work and closes owned connections, retaining durable data.
// Drain requests first. It is safe to call repeatedly, including on a nil store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closed.Store(true)
	if err := s.db.Close(); err != nil {
		return tokenrefresh.ErrUnavailable
	}
	return nil
}
