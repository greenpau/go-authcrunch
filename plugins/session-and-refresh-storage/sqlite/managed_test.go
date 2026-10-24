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
	"strings"
	"testing"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

func managedGeneration(namespace, generation string) tokenrefresh.Generation {
	return tokenrefresh.Generation{Namespace: strings.Repeat(namespace, 64), ID: strings.Repeat(generation, 64)}
}
func managedSession(id string, g tokenrefresh.Generation) tokenrefresh.Session {
	s := sessionFixture(id)
	s.Binding.Namespace = g.Namespace
	s.Binding.Generation = g.ID
	return s
}
func activateStore(t *testing.T, s *Store, g tokenrefresh.Generation) tokenrefresh.ActiveStore {
	t.Helper()
	view, err := s.ActivateGeneration(t.Context(), g)
	if err != nil || view == nil || view.Generation() != g {
		t.Fatal("generation activation failed", err)
	}
	return view
}
func managedCounts(t *testing.T, s *Store) (families, digests, markers int) {
	t.Helper()
	if err := s.db.QueryRow("SELECT (SELECT count(*) FROM refresh_families_v2),(SELECT count(*) FROM refresh_digests_v2),(SELECT count(*) FROM refresh_generations_v2)").Scan(&families, &digests, &markers); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSQLiteManagedMetadataReadiness(t *testing.T) {
	s := testStore(t, 2, 3)
	other := secondStore(t, s)
	metadata, err := s.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := tokenrefresh.NewExternalStoreConfig("other-name", "sqlite", 2, 3, s.config)
	if err != nil || metadata.Kind != expected.Kind || metadata.ConfigDigest != expected.ConfigDigest || metadata.MaxSessions != 2 || metadata.MaxRotations != 3 {
		t.Fatal("metadata does not attest normalized backend")
	}
	// A second reader allows readiness but would refuse any write COMMIT. No
	// namespace or probe family is created by this read-only public method.
	reader, err := other.db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.QueryRow("SELECT count(*) FROM sqlite_schema").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReady(t.Context()); err != nil {
		t.Fatal("readiness attempted mutation", err)
	}
	if f, d, g := managedCounts(t, s); f != 0 || d != 0 || g != 0 {
		t.Fatal("readiness created state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.CheckReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("readiness ignored cancellation")
	}
	if err := (*Store)(nil).CheckReady(t.Context()); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("nil store ready")
	}
	if _, err := (*Store)(nil).Metadata(); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("nil metadata accepted")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReady(t.Context()); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("closed store ready")
	}
	if _, err := s.Metadata(); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("closed metadata accepted")
	}
}

func TestSQLiteManagedGenerationRetirement(t *testing.T) {
	s := testStore(t, 3, 3)
	g := managedGeneration("a", "1")
	otherGeneration := managedGeneration("b", "1")
	first := activateStore(t, s, g)
	other := activateStore(t, s, otherGeneration)
	expiry := time.Now().Unix() + 60
	a, b, c := managedSession("a", g), managedSession("b", g), managedSession("c", otherGeneration)
	b.Binding.Portal = "second-portal"
	for _, entry := range []struct {
		view    tokenrefresh.ActiveStore
		session tokenrefresh.Session
	}{{first, a}, {first, b}, {other, c}} {
		if err := entry.view.Create(t.Context(), entry.session, expiry); err != nil {
			t.Fatal(err)
		}
	}
	next := sha256.Sum256([]byte("rotated-a"))
	if err := first.Rotate(t.Context(), a, next, a.IdleExpiresAt, expiry); err != nil {
		t.Fatal(err)
	}
	// The same generation survives independent connections and activation.
	reopened := secondStore(t, s)
	same := activateStore(t, reopened, g)
	if _, err := same.Lookup(t.Context(), next, a.Binding); err != nil {
		t.Fatal("same generation lost live state", err)
	}
	if f, d, n := managedCounts(t, s); f != 3 || d != 4 || n != 2 {
		t.Fatal("unexpected pre-retirement counts")
	}
	g2 := g
	g2.ID = strings.Repeat("2", 64)
	fresh := activateStore(t, reopened, g2)
	if f, d, n := managedCounts(t, s); f != 1 || d != 1 || n != 2 {
		t.Fatal("retirement did not remove all portal families and spent history")
	}
	freshSession := managedSession("fresh", g2)
	if err := fresh.Create(t.Context(), freshSession, expiry); err != nil {
		t.Fatal("retirement did not reclaim capacity", err)
	}
	beforeF, beforeD, beforeN := managedCounts(t, s)
	staleTests := []struct {
		name string
		run  func() error
	}{
		{"create", func() error { return first.Create(t.Context(), managedSession("stale", g), expiry) }},
		{"replace", func() error {
			return first.CreateReplacing(t.Context(), managedSession("replace", g), expiry, [][32]byte{freshSession.Current})
		}},
		{"lookup", func() error { _, err := first.Lookup(t.Context(), a.Current, a.Binding); return err }},
		{"rotate", func() error {
			return first.Rotate(t.Context(), a, sha256.Sum256([]byte("stale")), a.IdleExpiresAt, expiry)
		}},
		{"revoke", func() error { return first.Revoke(t.Context(), a.Current, a.Binding) }},
		{"validate", func() error { return first.ValidateSession(t.Context(), a.ID, a.Binding) }},
	}
	for _, tc := range staleTests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, tokenrefresh.ErrInvalid) {
				t.Fatal("stale view retained authority", err)
			}
			if f, d, n := managedCounts(t, s); f != beforeF || d != beforeD || n != beforeN {
				t.Fatal("stale view mutated current state")
			}
		})
	}
	if _, err := other.Lookup(t.Context(), c.Current, c.Binding); err != nil {
		t.Fatal("other namespace retired", err)
	}
	if _, err := fresh.Lookup(t.Context(), freshSession.Current, freshSession.Binding); err != nil {
		t.Fatal("stale operation revoked fresh family", err)
	}
}

func TestSQLiteManagedScopeAndGlobalLimits(t *testing.T) {
	s := testStore(t, 2, 2)
	aGen, bGen := managedGeneration("a", "1"), managedGeneration("b", "1")
	aView, bView := activateStore(t, s, aGen), activateStore(t, s, bGen)
	a, b := managedSession("a", aGen), managedSession("b", bGen)
	expiry := time.Now().Unix() + 60
	if err := aView.Create(t.Context(), a, expiry); err != nil {
		t.Fatal(err)
	}
	if err := bView.Create(t.Context(), b, expiry); err != nil {
		t.Fatal(err)
	}
	if err := bView.Create(t.Context(), managedSession("capacity", bGen), expiry); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("capacity was not file-wide")
	}
	// Wrong namespaces/bindings cannot consume replay evidence or revoke an
	// unrelated family, even with its exact current or spent digest.
	if _, err := bView.Lookup(t.Context(), a.Current, b.Binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("cross-namespace lookup accepted")
	}
	if err := bView.Revoke(t.Context(), a.Current, b.Binding); err != nil {
		t.Fatal(err)
	}
	wrong := a.Binding
	wrong.Namespace = bGen.Namespace
	if _, err := aView.Lookup(t.Context(), a.Current, wrong); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("view rewrote caller scope")
	}
	if err := aView.Rotate(t.Context(), a, b.Current, a.IdleExpiresAt, expiry); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("digest uniqueness was not file-wide")
	}
	// Concrete compatibility methods cannot bypass the marker by receiving a
	// managed binding. Empty-scope legacy access likewise cannot see managed rows.
	checks := []func() error{
		func() error { return s.Create(t.Context(), a, expiry) },
		func() error { return s.CreateReplacing(t.Context(), a, expiry, [][32]byte{b.Current}) },
		func() error { _, err := s.Lookup(t.Context(), a.Current, a.Binding); return err },
		func() error { return s.Rotate(t.Context(), a, sha256.Sum256([]byte("naked")), a.IdleExpiresAt, expiry) },
		func() error { return s.Revoke(t.Context(), a.Current, a.Binding) },
		func() error { return s.ValidateSession(t.Context(), a.ID, a.Binding) },
	}
	for _, check := range checks {
		if err := check(); !errors.Is(err, tokenrefresh.ErrInvalid) {
			t.Fatal("naked store accepted managed binding", err)
		}
	}
	legacy := a.Binding
	legacy.Namespace = ""
	legacy.Generation = ""
	if _, err := s.Lookup(t.Context(), a.Current, legacy); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("legacy scope accessed managed family")
	}
	if err := s.Revoke(t.Context(), a.Current, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := aView.Lookup(t.Context(), a.Current, a.Binding); err != nil {
		t.Fatal("rejected operation changed managed family", err)
	}
	if err := bView.Revoke(t.Context(), b.Current, b.Binding); err != nil {
		t.Fatal(err)
	}
	legacySession := sessionFixture("legacy")
	if err := s.Create(t.Context(), legacySession, expiry); err != nil {
		t.Fatal("legacy API compatibility lost", err)
	}
	if _, err := s.Lookup(t.Context(), legacySession.Current, legacySession.Binding); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteManagedActivationFailure(t *testing.T) {
	for _, phase := range []string{"invalid generation", "before commit", "reader contention", "attempted commit"} {
		t.Run(phase, func(t *testing.T) {
			s := testStore(t, 1, 2)
			g := managedGeneration("a", "1")
			view := activateStore(t, s, g)
			session := managedSession("live", g)
			if err := view.Create(t.Context(), session, time.Now().Unix()+60); err != nil {
				t.Fatal(err)
			}
			other := secondStore(t, s)
			g2 := g
			g2.ID = strings.Repeat("2", 64)
			ctx := t.Context()
			var reader *sql.Tx
			switch phase {
			case "invalid generation":
				g2.ID = "partial"
			case "before commit":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "reader contention":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
				var err error
				reader, err = other.db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Rollback()
				var n int
				if err := reader.QueryRow("SELECT count(*) FROM refresh_families_v2").Scan(&n); err != nil {
					t.Fatal(err)
				}
			case "attempted commit":
				setStoreCommitHook(t, s, func() int32 { return 1 })
			}
			candidate, err := s.ActivateGeneration(ctx, g2)
			if candidate != nil || err == nil {
				t.Fatal("failed activation published a view")
			}
			switch phase {
			case "invalid generation":
				if !errors.Is(err, tokenrefresh.ErrInvalid) {
					t.Fatal("wrong invalid generation error", err)
				}
			case "before commit":
				if !errors.Is(err, context.Canceled) || errors.Is(err, tokenrefresh.ErrCommitUncertain) {
					t.Fatal("safe cancellation misclassified", err)
				}
			case "attempted commit":
				if ErrCommitUncertain != tokenrefresh.ErrCommitUncertain || !errors.Is(err, tokenrefresh.ErrCommitUncertain) {
					t.Fatal("core uncertainty identity lost", err)
				}
				if err := s.CheckReady(t.Context()); !errors.Is(err, tokenrefresh.ErrUnavailable) {
					t.Fatal("uncertain handle not quarantined")
				}
			case "reader contention":
				if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCommitUncertain) {
					t.Fatal("reader contention was not rejected before activation", err)
				}
				if err := reader.Rollback(); err != nil {
					t.Fatal(err)
				}
				if err := s.CheckReady(t.Context()); err != nil {
					t.Fatal("reader contention quarantined the handle", err)
				}
			}
			// These rejected operations rolled back; this control is not permission for
			// an application to retry arbitrary ambiguous commits or issue credentials.
			recovered := activateStore(t, other, g)
			if _, err := recovered.Lookup(t.Context(), session.Current, session.Binding); err != nil {
				t.Fatal("failed activation lost original generation", err)
			}
		})
	}
}
