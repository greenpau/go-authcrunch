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
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	driver "modernc.org/sqlite"
)

func testStore(t *testing.T, capacity, rotations int) *Store {
	t.Helper()
	s, err := New(t.Context(), &Config{Path: filepath.Join(privateDir(t), "refresh ?#.db"), MaxSessions: capacity, MaxRotations: rotations})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func secondStore(t *testing.T, first *Store) *Store {
	t.Helper()
	s, err := New(t.Context(), &first.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func sessionFixture(id string) tokenrefresh.Session {
	now := time.Now().Unix()
	return tokenrefresh.Session{
		ID: id, Current: sha256.Sum256([]byte("fixture-" + id)), IdleExpiresAt: now + 300, AbsoluteExpiresAt: now + 600,
		Principal: tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: "immutable-alice", Subject: "alice", BackendVersion: "epoch", CredentialVersion: ^uint64(0), AuthTime: now, Methods: []string{"pwd"}, Challenges: []string{"password"}, Audience: []string{"api"}, Scopes: []string{"read"}},
		Binding:   tokenrefresh.Binding{Portal: "portal", Origin: "https://login.example.test", BasePath: "/auth", Transport: tokenrefresh.BodyTransport},
	}
}

func TestSQLiteConfigAndConstruction(t *testing.T) {
	path := filepath.Join(privateDir(t), "sessions.db")
	c := &Config{Path: path}
	s, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if c.MaxSessions != 0 || c.Timeout != "" {
		t.Fatal("constructor mutated config")
	}
	if s.config.MaxSessions != 10000 || s.config.MaxRotations != 1024 || s.config.Timeout != "1s" {
		t.Fatal("incorrect defaults")
	}
	if err := (*Config)(nil).Validate(); err == nil {
		t.Fatal("accepted nil config")
	}
	for _, c := range []Config{
		{}, {Path: "relative.db"}, {Path: "/"}, {Path: "file:/tmp/uri.db"}, {Path: path + "\n"}, {Path: "/tmp/\xff"},
		{Path: path, MaxSessions: -1}, {Path: path, MaxSessions: 100001}, {Path: path, MaxRotations: -1}, {Path: path, MaxRotations: 100001},
		{Path: path, Timeout: "bad"}, {Path: path, Timeout: "0"}, {Path: path, Timeout: "1us"}, {Path: path, Timeout: "31s"},
	} {
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted invalid config: %+v", c)
		}
	}
	for _, changed := range []Config{{Path: path, MaxSessions: 2}, {Path: path, MaxRotations: 2}} {
		if other, err := New(t.Context(), &changed); err == nil || other != nil {
			t.Fatal("accepted incompatible database limits")
		}
	}

	if other, err := New(t.Context(), nil); err == nil || other != nil {
		t.Fatal("accepted nil config")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		want := tokenrefresh.ErrUnavailable
		if input != nil {
			want = context.Canceled
		}
		if other, err := New(input, c); !errors.Is(err, want) || other != nil {
			t.Fatal("accepted invalid context", err)
		}
	}
	for _, mode := range []string{"symlink", "directory", "permissions", "parent permissions", "missing parent", "journal symlink", "corrupt", "foreign schema", "foreign schema lookalike", "future schema"} {
		t.Run(mode, func(t *testing.T) {
			parent := privateDir(t)
			path := filepath.Join(parent, "sensitive-name.db")
			switch mode {
			case "symlink":
				target := filepath.Join(parent, "target")
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "parent permissions":
				if err := os.Chmod(parent, 0755); err != nil {
					t.Fatal(err)
				}
			case "missing parent":
				path = filepath.Join(parent, "missing", "db")
			case "journal symlink":
				if err := os.Symlink(filepath.Join(parent, "target"), path+"-journal"); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("not a SQLite database"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign schema", "foreign schema lookalike", "future schema":
				if _, err := prepareFile(path); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				statement := "CREATE TABLE other(value TEXT)"
				if mode == "foreign schema lookalike" {
					statement = "CREATE TABLE sqliteX_foreign(value TEXT)"
				}
				if mode == "future schema" {
					statement = "PRAGMA user_version=99"
				}
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			other, err := New(t.Context(), &Config{Path: path})
			if err == nil || other != nil {
				t.Fatal("accepted unsafe database")
			}
			if strings.Contains(err.Error(), path) {
				t.Fatal("error disclosed database path")
			}
		})
	}
}

func TestSQLiteSnapshotsRestartAndReplay(t *testing.T) {
	s := testStore(t, 3, 10)
	original := sessionFixture("first")
	if err := s.Create(t.Context(), original, time.Now().Unix()+60); err != nil {
		t.Fatal(err)
	}
	original.Principal.Methods[0] = "changed"
	want := sessionFixture("first")
	want.Principal.AuthTime = original.Principal.AuthTime
	want.IdleExpiresAt = original.IdleExpiresAt
	want.AbsoluteExpiresAt = original.AbsoluteExpiresAt
	other := secondStore(t, s)
	got, err := other.Lookup(t.Context(), original.Current, original.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
	got.Principal.Audience[0] = "changed"
	previous, err := s.Lookup(t.Context(), original.Current, original.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if previous.Principal.Audience[0] != "api" {
		t.Fatal("caller changed persisted grant")
	}
	previous.Principal.Subject = "forged"
	previous.AbsoluteExpiresAt += 10000
	next := sha256.Sum256([]byte("next"))
	if err := other.Rotate(t.Context(), previous, next, original.IdleExpiresAt, time.Now().Unix()+60); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateSession(t.Context(), original.ID, original.Binding); err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := secondStore(t, s)
	current, err := restarted.Lookup(t.Context(), next, original.Binding)
	if err != nil || current.Revision != 1 || current.Principal.Subject != "alice" || current.AbsoluteExpiresAt != original.AbsoluteExpiresAt {
		t.Fatal("rotation changed original authority", err)
	}
	for _, field := range []string{"portal", "origin", "mount", "transport"} {
		bad := original.Binding
		switch field {
		case "portal":
			bad.Portal += "other"
		case "origin":
			bad.Origin += "other"
		case "mount":
			bad.BasePath += "other"
		case "transport":
			bad.Transport = tokenrefresh.CookieTransport
		}
		if _, err := s.Lookup(t.Context(), original.Current, bad); !errors.Is(err, tokenrefresh.ErrInvalid) {
			t.Fatal("wrong binding accepted")
		}
		if err := s.Revoke(t.Context(), next, bad); err != nil {
			t.Fatal(err)
		}
		if err := s.ValidateSession(t.Context(), original.ID, original.Binding); err != nil {
			t.Fatal("wrong binding revoked family")
		}
	}
	if _, err := restarted.Lookup(t.Context(), original.Current, original.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("spent credential accepted")
	}
	if _, err := s.Lookup(t.Context(), next, original.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("replay did not revoke descendant")
	}
	if err := restarted.Revoke(t.Context(), original.Current, original.Binding); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := secondStore(t, s)
	if err := reopened.ValidateSession(t.Context(), original.ID, original.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("restart revived revoked authority")
	}
}

func TestSQLiteAdmissionAndReplacement(t *testing.T) {
	s := testStore(t, 1, 3)
	other := secondStore(t, s)
	first, second := sessionFixture("first"), sessionFixture("second")
	expiry := time.Now().Unix() + 60
	if err := s.Create(t.Context(), first, expiry); err != nil {
		t.Fatal(err)
	}
	if err := other.Create(t.Context(), second, expiry); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("capacity not enforced")
	}
	wrong := second
	wrong.Binding.Portal = "other"
	if err := other.CreateReplacing(t.Context(), wrong, expiry, [][32]byte{first.Current}); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("cross binding replacement accepted")
	}
	if err := s.CreateReplacing(t.Context(), first, expiry, [][32]byte{first.Current}); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("replacement collision accepted")
	}
	// Fail after replacement has deleted the old row. The entire transaction
	// must roll back, restoring current and spent digest indexes as well.
	next := sha256.Sum256([]byte("replacement-spent"))
	if err := s.Rotate(t.Context(), first, next, first.IdleExpiresAt, expiry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_insert BEFORE INSERT ON digests BEGIN SELECT RAISE(ABORT,'private-canary'); END"); err != nil {
		t.Fatal(err)
	}
	err := other.CreateReplacing(t.Context(), second, expiry, [][32]byte{first.Current})
	if !errors.Is(err, tokenrefresh.ErrUnavailable) || strings.Contains(err.Error(), "private-canary") {
		t.Fatal("failed insertion leaked or succeeded", err)
	}
	if _, err := s.Lookup(t.Context(), next, first.Binding); err != nil {
		t.Fatal("failed replacement spent credential", err)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_insert"); err != nil {
		t.Fatal(err)
	}
	if err := other.CreateReplacing(t.Context(), second, expiry, [][32]byte{first.Current, first.Current, {}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateSession(t.Context(), first.ID, first.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("old family survives replacement")
	}
	if _, err := s.Lookup(t.Context(), second.Current, second.Binding); err != nil {
		t.Fatal(err)
	}
	if err := other.Revoke(t.Context(), second.Current, second.Binding); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(t.Context(), sessionFixture("third"), expiry); err != nil {
		t.Fatal("terminal family retained capacity", err)
	}
}

func TestSQLiteConcurrentClients(t *testing.T) {
	for _, operation := range []string{"create", "rotate", "replace"} {
		t.Run(operation, func(t *testing.T) {
			a := testStore(t, 1, 10)
			b := secondStore(t, a)
			previous := sessionFixture("previous")
			expiry := time.Now().Unix() + 60
			if operation != "create" {
				if err := a.Create(t.Context(), previous, expiry); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var group sync.WaitGroup
			for i, s := range []*Store{a, b} {
				group.Go(func() {
					<-start
					candidate := sessionFixture(fmt.Sprintf("candidate-%d", i))
					var err error
					switch operation {
					case "create":
						err = s.Create(t.Context(), candidate, expiry)
					case "rotate":
						err = s.Rotate(t.Context(), previous, candidate.Current, previous.IdleExpiresAt, expiry)
					case "replace":
						err = s.CreateReplacing(t.Context(), candidate, expiry, [][32]byte{previous.Current})
					}
					results <- err
				})
			}
			close(start)
			group.Wait()
			close(results)
			wins := 0
			for err := range results {
				if err == nil {
					wins++
				} else if !errors.Is(err, tokenrefresh.ErrInvalid) && !errors.Is(err, tokenrefresh.ErrUnavailable) {
					t.Fatal(err)
				}
			}
			if wins != 1 {
				t.Fatalf("expected one atomic winner, got %d", wins)
			}
			if operation == "rotate" {
				if err := b.ValidateSession(t.Context(), previous.ID, previous.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
					t.Fatal("concurrent reuse did not revoke winner")
				}
			}
		})
	}
}

func TestSQLiteBoundsExpiryAndRejection(t *testing.T) {
	for _, scenario := range []string{"idle", "absolute", "rotation limit", "revision", "id", "next collision", "invalid deadlines", "cancelled", "closed", "corrupt record", "missing file"} {
		t.Run(scenario, func(t *testing.T) {
			s := testStore(t, 2, 1)
			original := sessionFixture("first")
			expiry := time.Now().Unix() + 60
			if scenario == "absolute" {
				original.IdleExpiresAt = original.AbsoluteExpiresAt
			}
			if err := s.Create(t.Context(), original, expiry); err != nil {
				t.Fatal(err)
			}
			previous := original
			next := sha256.Sum256([]byte("next"))
			ctx := t.Context()
			idle := original.IdleExpiresAt
			switch scenario {
			case "idle":
				s.now = func() time.Time { return time.Unix(original.IdleExpiresAt, 0) }
			case "absolute":
				s.now = func() time.Time { return time.Unix(original.AbsoluteExpiresAt, 0) }
			case "rotation limit":
				if err := s.Rotate(ctx, original, next, idle, expiry); err != nil {
					t.Fatal(err)
				}
				var err error
				previous, err = s.Lookup(ctx, next, original.Binding)
				if err != nil {
					t.Fatal(err)
				}
				next = sha256.Sum256([]byte("too many"))
			case "revision":
				previous.Revision++
			case "id":
				previous.ID = "wrong"
			case "next collision":
				next = original.Current
			case "invalid deadlines":
				idle = original.AbsoluteExpiresAt + 1
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			case "corrupt record":
				if _, err := s.db.Exec("UPDATE families SET payload=?", []byte("{}")); err != nil {
					t.Fatal(err)
				}
			case "missing file":
				if err := os.Rename(s.config.Path, s.config.Path+".removed"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Rotate(ctx, previous, next, idle, expiry); err == nil {
				t.Fatal("invalid rotation accepted")
			}
			if scenario == "revision" || scenario == "id" || scenario == "next collision" || scenario == "invalid deadlines" || scenario == "cancelled" {
				if _, err := s.Lookup(t.Context(), original.Current, original.Binding); err != nil {
					t.Fatal("rejected rotation spent original", err)
				}
			}
			if scenario == "rotation limit" || scenario == "idle" || scenario == "absolute" {
				var count int
				if err := s.db.QueryRow("SELECT count(*) FROM digests").Scan(&count); err != nil || count != 0 {
					t.Fatal("terminal family retained history", count, err)
				}
			}
		})
	}
}

func TestSQLiteLockCancellationAndCommitFailure(t *testing.T) {
	s := testStore(t, 2, 10)
	other := secondStore(t, s)
	first := sessionFixture("first")
	expiry := time.Now().Unix() + 60
	if err := s.Create(t.Context(), first, expiry); err != nil {
		t.Fatal(err)
	}
	locked, err := other.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	err = s.Rotate(ctx, first, sha256.Sum256([]byte("blocked")), first.IdleExpiresAt, expiry)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lock wait ignored deadline", err)
	}
	if err := locked.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(t.Context(), first.Current, first.Binding); err != nil {
		t.Fatal("lock failure spent current", err)
	}
	reader, err := other.db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reader.QueryRow("SELECT count(*) FROM families").Scan(&n); err != nil {
		t.Fatal(err)
	}
	err = s.Rotate(t.Context(), first, sha256.Sum256([]byte("commit fails")), first.IdleExpiresAt, expiry)
	if !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("failed commit not identified", err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(t.Context(), first.Current, first.Binding); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("uncertain handle remained usable")
	}
	// SQLite rolled back this concrete busy commit. Another connection observes
	// the unchanged family; this is test evidence, not permission to retry an
	// arbitrary ambiguous commit in an application.
	if _, err := other.Lookup(t.Context(), first.Current, first.Binding); err != nil {
		t.Fatal("busy commit was not rolled back", err)
	}
}

func TestSQLiteConcurrentFilePreparation(t *testing.T) {
	const clients = 8
	config := &Config{Path: filepath.Join(privateDir(t), "concurrent.db"), MaxSessions: clients, Timeout: "5s"}
	start := make(chan struct{})
	var files [clients]os.FileInfo
	var failures [clients]error
	var workers sync.WaitGroup
	for i := range clients {
		workers.Go(func() {
			<-start
			files[i], failures[i] = prepareFile(config.Path)
		})
	}
	close(start)
	workers.Wait()
	for i := range clients {
		if failures[i] != nil {
			t.Fatal("concurrent file preparation failed", failures[i])
		}
		if !os.SameFile(files[0], files[i]) || files[i].Mode().Perm() != 0600 {
			t.Fatal("constructors did not converge on one private file")
		}
	}
	s, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	session := sessionFixture("initial")
	if err := s.Create(t.Context(), session, time.Now().Unix()+60); err != nil {
		t.Fatal(err)
	}
	info, err := prepareFile(config.Path)
	if err != nil || !os.SameFile(files[0], info) {
		t.Fatal("preparation replaced the existing database", err)
	}
	if _, err := s.Lookup(t.Context(), session.Current, session.Binding); err != nil {
		t.Fatal("preparation lost committed state", err)
	}
	entries, err := os.ReadDir(filepath.Dir(config.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".authcrunch-sqlite-") {
			t.Fatal("initialization left a temporary file")
		}
	}
}

func TestSQLiteRequestFailurePreservesHealthyHandle(t *testing.T) {
	for _, phase := range []string{"before commit", "during commit", "after commit deadline"} {
		t.Run(phase, func(t *testing.T) {
			s := testStore(t, 2, 10)
			first, unrelated := sessionFixture("first"), sessionFixture("unrelated")
			base := time.Now().Unix()
			for _, session := range []tokenrefresh.Session{first, unrelated} {
				if err := s.Create(t.Context(), session, base+60); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			s.now = func() time.Time {
				calls++
				if phase == "before commit" && calls == 3 {
					cancel()
				}
				if phase == "after commit deadline" && calls == 4 {
					return time.Unix(base+60, 0)
				}
				return time.Unix(base, 0)
			}
			if phase == "during commit" {
				setHook := func(hook driver.CommitHookFn) {
					conn, err := s.db.Conn(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					err = conn.Raw(func(raw any) error {
						raw.(interface{ RegisterCommitHook(driver.CommitHookFn) }).RegisterCommitHook(hook)
						return nil
					})
					if closeErr := conn.Close(); err != nil || closeErr != nil {
						t.Fatal("configure commit hook", err, closeErr)
					}
				}
				// Cancel from SQLite's actual commit hook, after database/sql has
				// handed COMMIT to the driver. The commit itself still succeeds.
				setHook(func() int32 { cancel(); return 0 })
				defer setHook(nil)
			}
			next := sha256.Sum256([]byte("request-failure-next"))
			err := s.Rotate(ctx, first, next, base+120, base+60)
			want := ErrCommitUncertain
			current := next
			if phase == "before commit" {
				want, current = context.Canceled, first.Current
			}
			if !errors.Is(err, want) {
				t.Fatalf("request failure: got %v, want %v", err, want)
			}
			s.now = func() time.Time { return time.Unix(base, 0) }
			if _, err := s.Lookup(t.Context(), unrelated.Current, unrelated.Binding); err != nil {
				t.Fatal("request-local failure disabled an unrelated family", err)
			}
			if _, err := s.Lookup(t.Context(), current, first.Binding); err != nil {
				t.Fatal("unexpected persisted commit outcome", err)
			}
		})
	}
}

func TestSQLiteRecordValidation(t *testing.T) {
	original := sessionFixture("first")
	for _, mode := range []string{"zero digest", "missing identity", "invalid UTF8", "list bound", "text bound", "encoded bound"} {
		s := sessionFixture("first")
		switch mode {
		case "zero digest":
			s.Current = [32]byte{}
		case "missing identity":
			s.Principal.UserID = ""
		case "invalid UTF8":
			s.Principal.Subject = "\xff"
		case "list bound":
			s.Principal.Methods = make([]string, 129)
		case "text bound":
			s.Principal.Subject = strings.Repeat("a", 4097)
		case "encoded bound":
			for range 100 {
				s.Principal.Scopes = append(s.Principal.Scopes, strings.Repeat("a", 4096))
			}
		}
		if _, err := encodeSession(s); !errors.Is(err, tokenrefresh.ErrInvalid) {
			t.Fatal("invalid record accepted", mode)
		}
	}
	data, err := encodeSession(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("null"), []byte("{}"), append(append([]byte{}, data...), byte(' ')), append(append([]byte{}, data...), []byte("{}")...), []byte(strings.Repeat(" ", 65537)), []byte(strings.Replace(string(data), `"ID":`, `"id":`, 1))} {
		if _, err := decodeSession(bad); !errors.Is(err, tokenrefresh.ErrUnavailable) {
			t.Fatal("noncanonical record accepted")
		}
	}
	got, err := decodeSession(data)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(original, got); diff != "" {
		t.Fatal(diff)
	}
	var missing *Store
	if err := missing.Create(t.Context(), original, time.Now().Unix()+60); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("nil store accepted creation")
	}
	if err := missing.Close(); err != nil {
		t.Fatal(err)
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Expiry after the transaction's first read must not extend an expired grant.
func TestSQLiteRotationRechecksOriginalIdleDeadline(t *testing.T) {
	s := testStore(t, 2, 8)
	first := sessionFixture("deadline")
	base := time.Now().Unix()
	first.IdleExpiresAt = base + 10
	if err := s.Create(t.Context(), first, base+60); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.now = func() time.Time {
		calls++
		if calls >= 3 {
			return time.Unix(first.IdleExpiresAt, 0)
		}
		return time.Unix(base, 0)
	}
	next := sha256.Sum256([]byte("deadline-next"))
	if err := s.Rotate(t.Context(), first, next, base+120, base+60); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("rotation extended a grant that expired before commit", err)
	}
	s.now = func() time.Time { return time.Unix(base, 0) }
	if _, err := s.Lookup(t.Context(), first.Current, first.Binding); err != nil {
		t.Fatal("failed rotation changed persisted state", err)
	}
	if _, err := s.Lookup(t.Context(), next, first.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("failed rotation admitted next credential", err)
	}
}

func TestSQLiteRejectsAlteredSchema(t *testing.T) {
	for _, statement := range []string{
		"DROP INDEX digests_family",
		"ALTER TABLE families ADD COLUMN unexpected TEXT",
		"CREATE TABLE sqliteX_extra(value TEXT)",
		"CREATE TRIGGER unexpected AFTER INSERT ON families BEGIN DELETE FROM digests; END",
		"PRAGMA application_id=7",
		"PRAGMA user_version=2",
	} {
		s := testStore(t, 2, 8)
		if _, err := s.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
		if candidate, err := New(t.Context(), &s.config); !errors.Is(err, tokenrefresh.ErrUnavailable) || candidate != nil {
			t.Fatal("accepted modified schema", err)
		}
	}
}
