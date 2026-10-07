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

// Package sqlitedb owns private SQLite files for the reference plugins.
// It is an implementation detail, not an authentication or configuration API.
package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	driver "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// ErrUnavailable hides database paths, statements, and values from consumers.
var ErrUnavailable = errors.New("SQLite backend unavailable")

// ErrCommitUncertain forbids publishing results or blindly retrying a mutation.
var ErrCommitUncertain = errors.New("SQLite commit outcome uncertain")

// ErrConfig indicates invalid declarative settings without exposing their values.
var ErrConfig = errors.New("invalid SQLite backend configuration")

// Database owns a single private connection pool. Callers own Close.
type Database struct {
	db      *sql.DB
	path    string
	file    os.FileInfo
	timeout time.Duration
	closed  atomic.Bool
}

// ValidText checks bounded, nonempty identifiers and configuration text.
func ValidText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

// Normalize validates filesystem-independent settings and installs defaults.
func Normalize(path, timeout *string) error {
	if path == nil || timeout == nil || !ValidText(*path, 4096) || !filepath.IsAbs(*path) || filepath.Clean(*path) == string(filepath.Separator) {
		return ErrConfig
	}
	*path = filepath.Clean(*path)
	if *timeout == "" {
		*timeout = "1s"
	}
	d, err := time.ParseDuration(*timeout)
	if err != nil || d < time.Millisecond || d > 30*time.Second {
		return ErrConfig
	}
	return nil
}

// Open initializes a dedicated application/version-1 schema. Definitions are
// trusted SQL constants supplied by plugin code, never user configuration.
func Open(ctx context.Context, path, timeout string, application int, schema map[string]string) (*Database, error) {
	if ctx == nil || Normalize(&path, &timeout) != nil || application <= 0 || len(schema) == 0 || runtime.GOOS == "windows" {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := prepare(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	q := url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(0)", "foreign_keys(1)", "synchronous(EXTRA)", "fullfsync(1)", "secure_delete(1)"}}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: q.Encode()}
	connector, err := driver.NewConnector(uri.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	d, _ := time.ParseDuration(timeout)
	store := &Database{db: db, path: path, file: info, timeout: d}
	err = store.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var mode string
		if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "delete" {
			return ErrUnavailable
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
				return ErrUnavailable
			}
			// application is a code-owned integer. PRAGMA has no parameter binding.
			if _, err := tx.ExecContext(ctx, "PRAGMA application_id="+strconv.Itoa(application)); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
				return err
			}
			for _, statement := range schema {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
			return nil
		}
		if app != application || version != 1 {
			return ErrUnavailable
		}
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
			if schema[name] != definition {
				return ErrUnavailable
			}
			count++
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if count != len(schema) {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func prepare(path string) (os.FileInfo, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	_, err = os.Lstat(path)
	if os.IsNotExist(err) {
		f, err := os.CreateTemp(filepath.Dir(path), ".authcrunch-sqlite-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil || closeErr != nil {
			return nil, ErrUnavailable
		}
		// Never publish a raw descriptor that another SQLite client could open.
		// Never overwrite an existing destination, including a concurrent winner.
		if err := os.Link(f.Name(), path); err != nil && !os.IsExist(err) {
			return nil, err
		}
		if err := os.Remove(f.Name()); err != nil {
			return nil, err
		}
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		syncErr = dir.Sync()
		closeErr = dir.Close()
		if syncErr != nil || closeErr != nil {
			return nil, ErrUnavailable
		}
	} else if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrUnavailable
	}
	return info, nil
}

func (s *Database) healthy() bool {
	parent, err := os.Lstat(filepath.Dir(s.path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return false
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		info, err := os.Lstat(s.path + suffix)
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

// Read provides a consistent snapshot. Its callback must not retain tx or
// publish results before Read returns successfully. No mutation is permitted.
func (s *Database) Read(ctx context.Context, apply func(context.Context, *sql.Tx) error) error {
	return s.run(ctx, false, apply)
}

// Write serializes mutations and commits once. Callbacks must not recursively
// enter this Database. SQL failures are redacted; domain errors are preserved.
func (s *Database) Write(ctx context.Context, apply func(context.Context, *sql.Tx) error) error {
	return s.run(ctx, true, apply)
}
func (s *Database) run(ctx context.Context, write bool, apply func(context.Context, *sql.Tx) error) error {
	if s == nil || s.db == nil || ctx == nil || apply == nil || s.closed.Load() {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.healthy() {
		return ErrUnavailable
	}
	var tx *sql.Tx
	for {
		var err error
		tx, err = s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: !write})
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var failure *driver.Error
		if !errors.As(err, &failure) || failure.Code()&255 != 5 {
			return ErrUnavailable
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
	if err := apply(ctx, tx); err != nil {
		return safeError(ctx, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.closed.Load() || !s.healthy() {
		return ErrUnavailable
	}
	if !write {
		if err := tx.Rollback(); err != nil {
			return safeError(ctx, err)
		}
		return ctx.Err()
	}
	if err := tx.Commit(); err != nil {
		if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, sql.ErrTxDone)) {
			return ctx.Err()
		}
		s.closed.Store(true)
		return ErrCommitUncertain
	}
	if ctx.Err() != nil {
		return errors.Join(ErrCommitUncertain, ctx.Err())
	}
	if s.closed.Load() || !s.healthy() {
		s.closed.Store(true)
		return ErrCommitUncertain
	}
	return nil
}
func safeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var failure *driver.Error
	if errors.As(err, &failure) || errors.Is(err, sql.ErrConnDone) || errors.Is(err, sql.ErrTxDone) {
		return ErrUnavailable
	}
	return err
}

// Close drains owned connections and preserves durable state. Hosts drain their
// requests first; an uncertain commit requires reconciliation before reopening.
func (s *Database) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closed.Store(true)
	if s.db.Close() != nil {
		return ErrUnavailable
	}
	return nil
}
