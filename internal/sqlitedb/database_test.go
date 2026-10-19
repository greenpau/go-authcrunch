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

package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func openTest(t *testing.T) (*Database, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "private ?#.db")
	db, err := Open(t.Context(), path, "1s", 71, map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}
func TestDatabaseTransactions(t *testing.T) {
	db, path := openTest(t)
	if err := db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO records VALUES(1,'first')")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("rejected")
	if err := db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE records SET value='second'"); err != nil {
			return err
		}
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	check := func(d *Database) {
		t.Helper()
		var value string
		if err := d.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, "SELECT value FROM records WHERE id=1").Scan(&value)
		}); err != nil || value != "first" {
			t.Fatal("rollback lost value", err)
		}
	}
	check(db)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := db.Read(ctx, func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(t.Context(), func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), path, "1s", 71, map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	check(reopened)
	if candidate, err := Open(t.Context(), path, "1s", 72, map[string]string{"other": "CREATE TABLE other (id TEXT)"}); err == nil || candidate != nil {
		t.Fatal("accepted foreign application")
	}
	if _, err := reopened.db.Exec("CREATE TABLE sqliteX_extra (id TEXT)"); err != nil {
		t.Fatal(err)
	}
	if candidate, err := Open(t.Context(), path, "1s", 71, map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"}); err == nil || candidate != nil {
		t.Fatal("accepted foreign schema")
	}
}

func TestDatabaseExclusiveTransactions(t *testing.T) {
	readerDB, path := openTest(t)
	schema := map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"}
	a, err := OpenExclusive(t.Context(), path, "1s", 71, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenExclusive(t.Context(), path, "1s", 71, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	reader, err := readerDB.db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.QueryRowContext(t.Context(), "SELECT count(*) FROM records").Scan(&count); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	called := false
	if err := a.Write(ctx, func(context.Context, *sql.Tx) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) || called || a.closed.Load() {
		t.Fatal("reader contention reached mutation or poisoned the handle", err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := a.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO records VALUES(1,'pending')")
		return err
	}); err != nil {
		t.Fatal("bounded admission did not recover", err)
	}
	writer, err := b.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	readCtx, cancelRead := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelRead()
	called = false
	if err := a.Read(readCtx, func(context.Context, *sql.Tx) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) || called || a.closed.Load() {
		t.Fatal("writer contention reached a read callback or poisoned the handle", err)
	}
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("already claimed")
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := range 32 {
		client := a
		if i%2 == 1 {
			client = b
		}
		wg.Go(func() {
			<-start
			err := client.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
				var state string
				if err := tx.QueryRowContext(ctx, "SELECT value FROM records WHERE id=1").Scan(&state); err != nil {
					return err
				}
				if state != "pending" {
					return rejected
				}
				_, err := tx.ExecContext(ctx, "UPDATE records SET value='claimed' WHERE id=1")
				return err
			})
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, rejected) {
				t.Error("concurrent claim failed", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("claims did not publish exactly one winner")
	}
	var state string
	if err := b.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT value FROM records WHERE id=1").Scan(&state)
	}); err != nil || state != "claimed" {
		t.Fatal("committed claim was not readable", err)
	}
}
func TestDatabaseFilesystemAndConfig(t *testing.T) {
	for _, mode := range []string{"missing parent", "public parent", "symlink", "public file"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "test.db")
			switch mode {
			case "missing parent":
				path = filepath.Join(dir, "absent", "test.db")
			case "public parent":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "public file":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("absent.db", path); err != nil {
					t.Fatal(err)
				}
			}
			if db, err := Open(t.Context(), path, "1s", 71, map[string]string{"records": "CREATE TABLE records (id TEXT)"}); err == nil || db != nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
	for _, path := range []string{"", "relative", "/", "/bad\x00path"} {
		timeout := ""
		if Normalize(&path, &timeout) == nil {
			t.Fatal("invalid path accepted")
		}
	}
	path := "/private/file"
	timeout := "31s"
	if Normalize(&path, &timeout) == nil {
		t.Fatal("timeout accepted")
	}
	db, _ := openTest(t)
	if err := os.Remove(db.path); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(t.Context(), func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing file accepted", err)
	}
}
func TestDatabaseLockAndCommitFailure(t *testing.T) {
	db, path := openTest(t)
	other, err := Open(t.Context(), path, "1s", 71, map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	writer, err := other.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := db.Write(ctx, func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unbounded lock wait", err)
	}
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	reader, err := other.db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := reader.QueryRow("SELECT count(*) FROM records").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO records VALUES(1,'secret')")
		return err
	}); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("commit failure not identified", err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(t.Context(), func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed handle reused", err)
	}
	if err := other.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT count(*) FROM records").Scan(&count)
	}); err != nil || count != 0 {
		t.Fatal("failed commit changed data", err)
	}
}

func TestDatabaseCanceledMutationDoesNotPoison(t *testing.T) {
	db, _ := openTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO records VALUES(1,'discard')"); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCommitUncertain) {
		t.Fatal("cancellation classification", err)
	}
	var count int
	if err := db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT count(*) FROM records").Scan(&count)
	}); err != nil || count != 0 {
		t.Fatal("canceled write persisted or poisoned handle", err)
	}
	if err := db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO records VALUES(2,'retained')")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseMigrationIsAtomicAndPinned(t *testing.T) {
	previous := map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)"}
	current := map[string]string{"records": "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT, return_url TEXT NOT NULL DEFAULT '')"}
	upgrade := []string{"ALTER TABLE records ADD COLUMN return_url TEXT NOT NULL DEFAULT ''"}
	for _, scenario := range []string{"upgrade", "fresh", "rollback", "foreign schema", "future version"} {
		t.Run(scenario, func(t *testing.T) {
			db, file := openTest(t)
			if _, err := db.db.Exec("INSERT INTO records VALUES(1,'retained')"); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "fresh":
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				file = filepath.Join(filepath.Dir(file), "fresh.db")
			case "foreign schema":
				if _, err := db.db.Exec("CREATE TABLE extra (id TEXT)"); err != nil {
					t.Fatal(err)
				}
			case "future version":
				if _, err := db.db.Exec("PRAGMA user_version=3"); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			statements := upgrade
			if scenario == "rollback" {
				statements = append(append([]string{}, upgrade...), "invalid SQL")
			}
			migrated, err := OpenMigrated(t.Context(), file, "1s", 71, current, previous, statements)
			if scenario == "rollback" || scenario == "foreign schema" || scenario == "future version" {
				if err == nil || migrated != nil {
					t.Fatal("unsafe migration accepted")
				}
				if scenario == "rollback" {
					restored, err := Open(t.Context(), file, "1s", 71, previous)
					if err != nil {
						t.Fatal("migration was not rolled back", err)
					}
					restored.Close()
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "upgrade" {
				var value, destination string
				if err := migrated.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
					return tx.QueryRowContext(ctx, "SELECT value,return_url FROM records WHERE id=1").Scan(&value, &destination)
				}); err != nil || value != "retained" || destination != "" {
					t.Fatal("migration changed data", err)
				}
			}
			migrated.Close()
			reopened, err := OpenMigrated(t.Context(), file, "1s", 71, current, previous, upgrade)
			if err != nil {
				t.Fatal(err)
			}
			reopened.Close()
			if downgraded, err := Open(t.Context(), file, "1s", 71, previous); err == nil || downgraded != nil {
				t.Fatal("old binary accepted upgraded database")
			}
		})
	}
}
