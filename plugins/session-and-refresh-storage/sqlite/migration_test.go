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
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func encodeV1Fixture(t *testing.T, s tokenrefresh.Session) []byte {
	t.Helper()
	record := sessionRecordV1{ID: s.ID, ExternalIdentity: externalRecord(s.Principal.ExternalIdentity), Principal: principalRecord(s.Principal), Binding: bindingRecordV1{s.Binding.Portal, s.Binding.Origin, s.Binding.BasePath, s.Binding.Transport}, Current: s.Current, Revision: s.Revision, IdleExpiresAt: s.IdleExpiresAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func legacyDatabase(t *testing.T, sessions []tokenrefresh.Session, history map[string][][32]byte) (Config, *sql.DB) {
	t.Helper()
	cfg := Config{Path: filepath.Join(privateDir(t), "legacy.db"), MaxSessions: 3, MaxRotations: 3, Timeout: "5s"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareFile(cfg.Path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	for _, object := range schemaV1 {
		if _, err := db.Exec(object.sql); err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{"PRAGMA application_id=1094931014", "PRAGMA user_version=1", "INSERT INTO settings VALUES(1,3,3)"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, session := range sessions {
		if _, err := db.Exec("INSERT INTO families(id,payload,expires_at) VALUES(?,?,?)", session.ID, encodeV1Fixture(t, session), session.IdleExpiresAt); err != nil {
			t.Fatal(err)
		}
		digests := history[session.ID]
		if digests == nil {
			digests = [][32]byte{session.Current}
		}
		for _, digest := range digests {
			if _, err := db.Exec("INSERT INTO digests(digest,family) VALUES(?,?)", digest[:], session.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	return cfg, db
}
func migrationSession(t *testing.T) tokenrefresh.Session {
	t.Helper()
	s := sessionFixture("provider")
	s.Principal.Source = tokenrefresh.ProviderSnapshotSource
	s.Principal.Backend = "upstream"
	s.Principal.BackendKind = "oauth"
	s.Principal.ProviderSnapshot = []byte(`{"sub":"upstream-alice","custom":{"tenant":"one"}}`)
	s.Principal.ExternalIdentity = requests.ExternalIdentity{Provider: "upstream", Kind: "oauth", Issuer: "https://issuer.example.test", Subject: "upstream-alice", Evidence: requests.AuthenticationEvidence{UserID: "attached-alice", BackendVersion: "epoch", CredentialVersion: 17, AuthenticatedAt: s.Principal.AuthTime, Method: "federated"}}
	return s
}

func TestSQLiteV1MigrationPreservesLegacyEvidence(t *testing.T) {
	local, provider := sessionFixture("local"), migrationSession(t)
	spent := local.Current
	local.Current = sha256.Sum256([]byte("legacy-next"))
	local.Revision = 1
	cfg, old := legacyDatabase(t, []tokenrefresh.Session{local, provider}, map[string][][32]byte{local.ID: {spent, local.Current}})
	// Retain a prepared old mutation on the old connection across migration.
	// A version check only on reopen would not protect this already-open reader.
	oldMutation, err := old.Prepare("DELETE FROM families WHERE id=?")
	if err != nil {
		t.Fatal(err)
	}
	defer oldMutation.Close()
	migrated, err := New(t.Context(), &cfg)
	if err != nil {
		t.Fatal("migration failed", err)
	}
	defer migrated.Close()
	for _, expected := range []tokenrefresh.Session{local, provider} {
		got, err := migrated.Lookup(t.Context(), expected.Current, expected.Binding)
		if err != nil || !cmp.Equal(expected, got) {
			t.Fatal("migration changed legacy authority or provider evidence", err)
		}
	}
	if f, d, n := managedCounts(t, migrated); f != 2 || d != 3 || n != 0 {
		t.Fatal("migration lost history or adopted a managed namespace")
	}
	var version int
	if err := old.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatal("migration did not publish the format boundary", err)
	}
	if err := validateSchema(t.Context(), old, schemaV1[:]); err == nil {
		t.Fatal("old schema reader accepted migrated storage")
	}
	if _, err := oldMutation.Exec(local.ID); err == nil {
		t.Fatal("already-open legacy handle mutated new families")
	}
	if _, err := old.Exec("INSERT INTO digests(digest,family) VALUES(?,?)", spent[:], provider.ID); err == nil {
		t.Fatal("already-open legacy history writer retained authority")
	}
	if f, d, n := managedCounts(t, migrated); f != 2 || d != 3 || n != 0 {
		t.Fatal("old SQL changed migrated storage")
	}
	view := activateStore(t, migrated, managedGeneration("a", "1"))
	wrong := local.Binding
	wrong.Namespace = view.Generation().Namespace
	wrong.Generation = view.Generation().ID
	if _, err := view.Lookup(t.Context(), local.Current, wrong); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("managed view implicitly adopted migrated family")
	}
	if _, err := migrated.Lookup(t.Context(), spent, local.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("spent credential lost replay authority")
	}
	if _, err := migrated.Lookup(t.Context(), local.Current, local.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("replay did not revoke descendant")
	}
	if _, err := migrated.Lookup(t.Context(), provider.Current, provider.Binding); err != nil {
		t.Fatal("replay changed other migrated family", err)
	}
	reopened := secondStore(t, migrated)
	if _, err := reopened.Lookup(t.Context(), provider.Current, provider.Binding); err != nil {
		t.Fatal("migrated record failed reopen", err)
	}
}

func TestSQLiteV1MigrationMaximumPayload(t *testing.T) {
	original := sessionFixture("maximum-legacy")
	original.Principal.Methods = make([]string, 17)
	for i := range 16 {
		original.Principal.Methods[i] = strings.Repeat("x", 3900)
	}
	padding := 65536 - len(encodeV1Fixture(t, original))
	if padding <= 0 || padding > 4096 {
		t.Fatal("maximum-payload fixture cannot meet individual field bounds")
	}
	original.Principal.Methods[16] = strings.Repeat("p", padding)
	payload := encodeV1Fixture(t, original)
	if len(payload) != 65536 || !validSession(original) {
		t.Fatal("maximum-payload fixture does not meet the legacy record contract")
	}
	cfg, old := legacyDatabase(t, []tokenrefresh.Session{original}, nil)
	migrated, err := New(t.Context(), &cfg)
	if err != nil {
		t.Fatal("valid maximum-sized legacy record failed migration", err)
	}
	defer migrated.Close()
	got, err := migrated.Lookup(t.Context(), original.Current, original.Binding)
	if err != nil || !cmp.Equal(original, got) {
		t.Fatal("maximum-sized migration changed legacy authority", err)
	}
	var after []byte
	if err := old.QueryRow("SELECT payload FROM refresh_families_v2 WHERE id=?", original.ID).Scan(&after); err != nil || !bytes.Equal(after, payload) {
		t.Fatal("empty scope changed maximum-sized legacy bytes", err)
	}
}

func TestSQLiteV1MigrationRejectsBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"limits", "extra schema", "wrong payload", "duplicate field", "scope injection", "zero external proof", "wrong expiry", "missing current", "missing spent", "extra spent", "rotation overflow", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			original := sessionFixture("legacy")
			cfg, old := legacyDatabase(t, []tokenrefresh.Session{original}, nil)
			payload := encodeV1Fixture(t, original)
			switch scenario {
			case "limits":
				cfg.MaxSessions++
			case "extra schema":
				if _, err := old.Exec("CREATE TABLE extra(value TEXT)"); err != nil {
					t.Fatal(err)
				}
			case "wrong payload":
				payload = []byte(`{}`)
			case "duplicate field":
				payload = bytes.Replace(payload, []byte(`"ID":"legacy"`), []byte(`"ID":"legacy","ID":"legacy"`), 1)
			case "scope injection":
				payload = bytes.Replace(payload, []byte(`"Binding":{`), []byte(`"Binding":{"Namespace":"`+strings.Repeat("a", 64)+`",`), 1)
			case "zero external proof":
				var record sessionRecordV1
				if err := json.Unmarshal(payload, &record); err != nil {
					t.Fatal(err)
				}
				record.ExternalIdentity = &externalIdentityRecord{}
				var err error
				payload, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong expiry":
				if _, err := old.Exec("UPDATE families SET expires_at=expires_at+1"); err != nil {
					t.Fatal(err)
				}
			case "missing current":
				if _, err := old.Exec("DELETE FROM digests"); err != nil {
					t.Fatal(err)
				}
			case "missing spent":
				original.Revision = 1
				payload = encodeV1Fixture(t, original)
			case "extra spent":
				other := sha256.Sum256([]byte("extra"))
				if _, err := old.Exec("INSERT INTO digests VALUES(?,?)", other[:], original.ID); err != nil {
					t.Fatal(err)
				}
			case "rotation overflow":
				original.Revision = 4
				payload = encodeV1Fixture(t, original)
			}
			if _, err := old.Exec("UPDATE families SET payload=?", payload); err != nil {
				t.Fatal(err)
			}
			var beforeExpiry int64
			var beforeDigests int
			if err := old.QueryRow("SELECT expires_at FROM families").Scan(&beforeExpiry); err != nil {
				t.Fatal(err)
			}
			if err := old.QueryRow("SELECT count(*) FROM digests").Scan(&beforeDigests); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if scenario == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			candidate, err := New(ctx, &cfg)
			if err == nil || candidate != nil {
				t.Fatal("invalid old database migrated")
			}
			var version, v2, count int
			var after []byte
			var expiry int64
			if err := old.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
				t.Fatal("failed migration changed schema version", err)
			}
			if err := old.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name LIKE '%_v2'").Scan(&v2); err != nil || v2 != 0 {
				t.Fatal("failed migration left new schema", err)
			}
			if err := old.QueryRow("SELECT payload,expires_at FROM families").Scan(&after, &expiry); err != nil || !bytes.Equal(after, payload) || expiry != beforeExpiry {
				t.Fatal("failed migration changed original record", err)
			}
			if err := old.QueryRow("SELECT count(*) FROM digests").Scan(&count); err != nil || count != beforeDigests {
				t.Fatal("failed migration changed original history", err)
			}
		})
	}
}

func TestSQLiteV1MigrationReaderContention(t *testing.T) {
	original := sessionFixture("legacy")
	cfg, old := legacyDatabase(t, []tokenrefresh.Session{original}, nil)
	reader, err := old.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var n int
	if err := reader.QueryRow("SELECT count(*) FROM families").Scan(&n); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	candidate, err := New(ctx, &cfg)
	if candidate != nil || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCommitUncertain) {
		t.Fatal("reader contention was not rejected before migration", err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := old.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("blocked migration changed the schema", err)
	}
	// Recovery opens a new handle after observation of this concrete rollback;
	// the failed constructor did not publish a store or an activated view.
	reopened, err := New(t.Context(), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Lookup(t.Context(), original.Current, original.Binding); err != nil {
		t.Fatal("recovery lost legacy authority", err)
	}
}

func TestSQLiteV1MigrationCommitFailure(t *testing.T) {
	original := sessionFixture("legacy")
	cfg, old := legacyDatabase(t, []tokenrefresh.Session{original}, nil)
	info, err := os.Lstat(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise initialization on a real SQLite connection with a failing COMMIT
	// hook. Reader contention is resolved at admission, before migration begins.
	s := &Store{db: old, config: cfg, file: info, timeout: 5 * time.Second, now: time.Now}
	setStoreCommitHook(t, s, func() int32 { return 1 })
	err = s.transact(t.Context(), nil, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		return true, s.initialize(ctx, tx)
	})
	setStoreCommitHook(t, s, nil)
	if !errors.Is(err, ErrCommitUncertain) || !s.closed.Load() {
		t.Fatal("migration commit failure was not quarantined", err)
	}
	var version, newTables int
	if err := old.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("failed migration changed the schema version", err)
	}
	if err := old.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name GLOB '*_v2'").Scan(&newTables); err != nil || newTables != 0 {
		t.Fatal("failed migration left new schema objects", err)
	}
	reopened, err := New(t.Context(), &cfg)
	if err != nil {
		t.Fatal("reopen after rejected migration commit", err)
	}
	defer reopened.Close()
	if _, err := reopened.Lookup(t.Context(), original.Current, original.Binding); err != nil {
		t.Fatal("failed migration lost legacy authority", err)
	}
}

func TestSQLiteMigrationAndManagedCapacityOne(t *testing.T) {
	cfg, old := legacyDatabase(t, nil, nil)
	if _, err := old.Exec("UPDATE settings SET max_sessions=1"); err != nil {
		t.Fatal(err)
	}
	cfg.MaxSessions = 1
	s, err := New(t.Context(), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g := managedGeneration("a", "1")
	v := activateStore(t, s, g)
	session := managedSession("old", g)
	expiry := time.Now().Unix() + 60
	if err := v.Create(t.Context(), session, expiry); err != nil {
		t.Fatal(err)
	}
	next := sha256.Sum256([]byte("next"))
	if err := v.Rotate(t.Context(), session, next, session.IdleExpiresAt, expiry); err != nil {
		t.Fatal(err)
	}
	g.ID = strings.Repeat("2", 64)
	replacement := activateStore(t, s, g)
	if f, d, _ := managedCounts(t, s); f != 0 || d != 0 {
		t.Fatal("generation change retained capacity/history")
	}
	if err := replacement.Create(t.Context(), managedSession("new", g), expiry); err != nil {
		t.Fatal("capacity-one generation could not accept fresh login", err)
	}
}
