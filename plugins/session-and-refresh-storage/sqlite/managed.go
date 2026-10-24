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
	"encoding/hex"
	"errors"
	"strings"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

var _ tokenrefresh.ManagedStore = (*Store)(nil)
var _ tokenrefresh.ActiveStore = (*activeStore)(nil)

type activeStore struct {
	store      *Store
	generation tokenrefresh.Generation
}

func validGeneration(g tokenrefresh.Generation) bool {
	for _, value := range []string{g.Namespace, g.ID} {
		if len(value) != 64 || strings.ToLower(value) != value {
			return false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return false
		}
	}
	return true
}
func validScope(g tokenrefresh.Generation) bool {
	return g == (tokenrefresh.Generation{}) || validGeneration(g)
}
func bindingScope(b tokenrefresh.Binding) tokenrefresh.Generation {
	return tokenrefresh.Generation{Namespace: b.Namespace, ID: b.Generation}
}

// Metadata describes the immutable initialized handle, without key/DB reads.
func (s *Store) Metadata() (tokenrefresh.StoreMetadata, error) {
	if s == nil || s.db == nil || s.closed.Load() {
		return tokenrefresh.StoreMetadata{}, tokenrefresh.ErrUnavailable
	}
	c, err := tokenrefresh.NewExternalStoreConfig("sqlite", "sqlite", s.config.MaxSessions, s.config.MaxRotations, s.config)
	if err != nil {
		return tokenrefresh.StoreMetadata{}, tokenrefresh.ErrUnavailable
	}
	return tokenrefresh.StoreMetadata{Kind: c.Kind, ConfigDigest: c.ConfigDigest, MaxSessions: c.MaxSessions, MaxRotations: c.MaxRotations}, nil
}

// CheckReady reads schema and limits on the owned SQLite connection. It never
// starts a write transaction, creates a record or opens an auxiliary file.
func (s *Store) CheckReady(ctx context.Context) error {
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
	var app, version int
	var journal string
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return safeError(ctx, err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return safeError(ctx, err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return safeError(ctx, err)
	}
	if app != applicationID || version != schemaVersion || journal != "delete" {
		return tokenrefresh.ErrUnavailable
	}
	if err := validateSchema(ctx, s.db, schema[:]); err != nil {
		return safeError(ctx, err)
	}
	if err := s.validateLimits(ctx, s.db, "refresh_settings_v2"); err != nil {
		return safeError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() || !s.healthy() {
		return tokenrefresh.ErrUnavailable
	}
	return nil
}

// ActivateGeneration retires a namespace atomically. Returned views never track
// later activations: every operation checks their captured marker under its own
// transaction. The owning root state lock, not this marker, fences deployment.
func (s *Store) ActivateGeneration(ctx context.Context, g tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	if !validGeneration(g) {
		return nil, tokenrefresh.ErrInvalid
	}
	err := s.transact(ctx, nil, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		var current string
		err := tx.QueryRowContext(ctx, "SELECT generation FROM refresh_generations_v2 WHERE namespace=?", g.Namespace).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if err == nil && !validGeneration(tokenrefresh.Generation{Namespace: g.Namespace, ID: current}) {
			return false, tokenrefresh.ErrUnavailable
		}
		if err == nil && current == g.ID {
			return true, nil
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM refresh_families_v2 WHERE namespace=?", g.Namespace); err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO refresh_generations_v2(namespace,generation) VALUES(?,?) ON CONFLICT(namespace) DO UPDATE SET generation=excluded.generation", g.Namespace, g.ID)
		return err == nil, err
	})
	if err != nil {
		return nil, err
	}
	return &activeStore{store: s, generation: g}, nil
}

func (s *Store) transactScope(ctx context.Context, g tokenrefresh.Generation, beforeCommit func() error, action func(context.Context, *sql.Tx) (bool, error)) error {
	if !validScope(g) {
		return tokenrefresh.ErrInvalid
	}
	return s.transact(ctx, beforeCommit, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		if g != (tokenrefresh.Generation{}) {
			var current string
			if err := tx.QueryRowContext(ctx, "SELECT generation FROM refresh_generations_v2 WHERE namespace=?", g.Namespace).Scan(&current); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return false, tokenrefresh.ErrInvalid
				}
				return false, err
			}
			if !validGeneration(tokenrefresh.Generation{Namespace: g.Namespace, ID: current}) {
				return false, tokenrefresh.ErrUnavailable
			}
			if current != g.ID {
				return false, tokenrefresh.ErrInvalid
			}
		}
		return action(ctx, tx)
	})
}

func (v *activeStore) Generation() tokenrefresh.Generation {
	if v == nil {
		return tokenrefresh.Generation{}
	}
	return v.generation
}
func (v *activeStore) matches(b tokenrefresh.Binding) bool {
	return v != nil && v.store != nil && validGeneration(v.generation) && bindingScope(b) == v.generation
}
func (v *activeStore) Create(ctx context.Context, s tokenrefresh.Session, expiry int64) error {
	return v.CreateReplacing(ctx, s, expiry, nil)
}
func (v *activeStore) CreateReplacing(ctx context.Context, s tokenrefresh.Session, expiry int64, previous [][32]byte) error {
	if !v.matches(s.Binding) {
		return tokenrefresh.ErrInvalid
	}
	return v.store.createReplacing(ctx, v.generation, s, expiry, previous)
}
func (v *activeStore) Lookup(ctx context.Context, d [32]byte, b tokenrefresh.Binding) (tokenrefresh.Session, error) {
	if !v.matches(b) {
		return tokenrefresh.Session{}, tokenrefresh.ErrInvalid
	}
	return v.store.lookupScope(ctx, v.generation, d, b)
}
func (v *activeStore) Rotate(ctx context.Context, s tokenrefresh.Session, next [32]byte, idle, expiry int64) error {
	if !v.matches(s.Binding) {
		return tokenrefresh.ErrInvalid
	}
	return v.store.rotate(ctx, v.generation, s, next, idle, expiry)
}
func (v *activeStore) Revoke(ctx context.Context, d [32]byte, b tokenrefresh.Binding) error {
	if !v.matches(b) {
		return tokenrefresh.ErrInvalid
	}
	return v.store.revoke(ctx, v.generation, d, b)
}
func (v *activeStore) ValidateSession(ctx context.Context, id string, b tokenrefresh.Binding) error {
	if !v.matches(b) {
		return tokenrefresh.ErrInvalid
	}
	return v.store.validateSession(ctx, v.generation, id, b)
}

// Create stores a family with legacy empty-scope authority. Managed
// credentials must use an activated immutable view, never a naked Store handle.
func (s *Store) Create(ctx context.Context, v tokenrefresh.Session, expiry int64) error {
	return s.CreateReplacing(ctx, v, expiry, nil)
}

// CreateReplacing atomically replaces matching legacy empty-scope families.
func (s *Store) CreateReplacing(ctx context.Context, v tokenrefresh.Session, expiry int64, previous [][32]byte) error {
	if bindingScope(v.Binding) != (tokenrefresh.Generation{}) {
		return tokenrefresh.ErrInvalid
	}
	return s.createReplacing(ctx, tokenrefresh.Generation{}, v, expiry, previous)
}

// Lookup resolves a credential only within the legacy empty scope.
func (s *Store) Lookup(ctx context.Context, d [32]byte, b tokenrefresh.Binding) (tokenrefresh.Session, error) {
	if bindingScope(b) != (tokenrefresh.Generation{}) {
		return tokenrefresh.Session{}, tokenrefresh.ErrInvalid
	}
	return s.lookupScope(ctx, tokenrefresh.Generation{}, d, b)
}

// Rotate atomically advances a legacy empty-scope family and its replay history.
func (s *Store) Rotate(ctx context.Context, v tokenrefresh.Session, next [32]byte, idle, expiry int64) error {
	if bindingScope(v.Binding) != (tokenrefresh.Generation{}) {
		return tokenrefresh.ErrInvalid
	}
	return s.rotate(ctx, tokenrefresh.Generation{}, v, next, idle, expiry)
}

// Revoke invalidates the legacy empty-scope family matching a credential.
func (s *Store) Revoke(ctx context.Context, d [32]byte, b tokenrefresh.Binding) error {
	if bindingScope(b) != (tokenrefresh.Generation{}) {
		return tokenrefresh.ErrInvalid
	}
	return s.revoke(ctx, tokenrefresh.Generation{}, d, b)
}

// ValidateSession checks a legacy empty-scope family's current authority.
func (s *Store) ValidateSession(ctx context.Context, id string, b tokenrefresh.Binding) error {
	if bindingScope(b) != (tokenrefresh.Generation{}) {
		return tokenrefresh.ErrInvalid
	}
	return s.validateSession(ctx, tokenrefresh.Generation{}, id, b)
}
