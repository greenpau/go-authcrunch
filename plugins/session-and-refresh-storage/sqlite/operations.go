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

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

// CreateReplacing atomically retires matching previous families and creates the
// new one. Failure preserves every live family, even at capacity. Only trusted
// fresh-login callers may use previous credentials as replacement targets.
func (s *Store) createReplacing(ctx context.Context, scope tokenrefresh.Generation, session tokenrefresh.Session, accessExpiry int64, previous [][32]byte) error {
	if session.Revision != 0 || len(previous) > 128 {
		return tokenrefresh.ErrInvalid
	}
	data, err := encodeSession(session)
	if err != nil {
		return err
	}
	check := func() error {
		now := s.now().Unix()
		if accessExpiry <= now || accessExpiry > session.AbsoluteExpiresAt || session.IdleExpiresAt <= now || session.Principal.AuthTime > now {
			return tokenrefresh.ErrInvalid
		}
		return nil
	}
	return s.transactScope(ctx, scope, check, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		if err := check(); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM refresh_families_v2 WHERE expires_at<=?", s.now().Unix()); err != nil {
			return false, err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM refresh_families_v2 WHERE id=?) + (SELECT count(*) FROM refresh_digests_v2 WHERE digest=?)", session.ID, session.Current[:]).Scan(&count); err != nil {
			return false, err
		}
		// Check collisions before removing replacement targets.
		if count != 0 {
			return false, tokenrefresh.ErrUnavailable
		}
		retired := make(map[string]bool)
		for _, digest := range previous {
			old, err := loadDigest(ctx, tx, digest, scope)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return false, err
			}
			if old.Binding == session.Binding {
				retired[old.ID] = true
			}
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM refresh_families_v2").Scan(&count); err != nil {
			return false, err
		}
		if count-len(retired) >= s.config.MaxSessions {
			return false, tokenrefresh.ErrUnavailable
		}
		for id := range retired {
			if err := deleteFamily(ctx, tx, id, scope); err != nil {
				return false, err
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO refresh_families_v2(id,namespace,generation,payload,expires_at) VALUES(?,?,?,?,?)", session.ID, scope.Namespace, scope.ID, data, session.IdleExpiresAt); err != nil {
			return false, err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO refresh_digests_v2(digest,family) VALUES(?,?)", session.Current[:], session.ID)
		return err == nil, err
	})
}

func loadDigest(ctx context.Context, tx *sql.Tx, digest [32]byte, scope tokenrefresh.Generation) (tokenrefresh.Session, error) {
	var id string
	var data []byte
	var expiry int64
	if err := tx.QueryRowContext(ctx, "SELECT f.id,f.payload,f.expires_at FROM refresh_families_v2 f JOIN refresh_digests_v2 d ON d.family=f.id WHERE d.digest=? AND f.namespace=? AND f.generation=?", digest[:], scope.Namespace, scope.ID).Scan(&id, &data, &expiry); err != nil {
		return tokenrefresh.Session{}, err
	}
	session, err := decodeSession(data)
	if err != nil || session.ID != id || bindingScope(session.Binding) != scope || session.IdleExpiresAt != expiry {
		return tokenrefresh.Session{}, tokenrefresh.ErrUnavailable
	}
	return session, nil
}

func deleteFamily(ctx context.Context, tx *sql.Tx, id string, scope tokenrefresh.Generation) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM refresh_families_v2 WHERE id=? AND namespace=? AND generation=?", id, scope.Namespace, scope.ID)
	return err
}

// lookup commits deletion on a matching spent/expired credential. A wrong
// binding or unknown digest can never revoke an unrelated family's authority.
func (s *Store) lookup(ctx context.Context, tx *sql.Tx, scope tokenrefresh.Generation, digest [32]byte, binding tokenrefresh.Binding) (tokenrefresh.Session, bool, error) {
	session, err := loadDigest(ctx, tx, digest, scope)
	if errors.Is(err, sql.ErrNoRows) {
		return tokenrefresh.Session{}, false, tokenrefresh.ErrInvalid
	}
	if err != nil {
		return tokenrefresh.Session{}, false, err
	}
	if session.Binding != binding {
		return tokenrefresh.Session{}, false, tokenrefresh.ErrInvalid
	}
	now := s.now().Unix()
	if session.Current != digest || now >= session.IdleExpiresAt || now >= session.AbsoluteExpiresAt {
		if err := deleteFamily(ctx, tx, session.ID, scope); err != nil {
			return tokenrefresh.Session{}, false, err
		}
		return tokenrefresh.Session{}, true, tokenrefresh.ErrInvalid
	}
	return session, false, nil
}

// Lookup returns an independent snapshot and durably revokes replayed families.
func (s *Store) lookupScope(ctx context.Context, scope tokenrefresh.Generation, digest [32]byte, binding tokenrefresh.Binding) (tokenrefresh.Session, error) {
	var session tokenrefresh.Session
	err := s.transactScope(ctx, scope, func() error {
		if s.now().Unix() >= session.IdleExpiresAt {
			return tokenrefresh.ErrInvalid
		}
		return nil
	}, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		var commit bool
		var err error
		session, commit, err = s.lookup(ctx, tx, scope, digest, binding)
		return commit || err == nil, err
	})
	if err != nil {
		return tokenrefresh.Session{}, err
	}
	return session, nil
}

// Rotate rechecks stored authority under a write transaction. Caller changes to
// principal or deadlines in the previous snapshot never change the stored grant.
func (s *Store) rotate(ctx context.Context, scope tokenrefresh.Generation, previous tokenrefresh.Session, next [32]byte, idleExpiry, accessExpiry int64) error {
	var absolute, previousIdle int64
	check := func() error {
		now := s.now().Unix()
		if now >= previousIdle {
			return tokenrefresh.ErrInvalid
		}
		if accessExpiry <= now {
			return tokenrefresh.ErrUnavailable
		}
		if idleExpiry <= now || idleExpiry > absolute || accessExpiry > absolute {
			return tokenrefresh.ErrInvalid
		}
		return nil
	}
	return s.transactScope(ctx, scope, check, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		current, commit, err := s.lookup(ctx, tx, scope, previous.Current, previous.Binding)
		if err != nil {
			return commit, err
		}
		if previous.ID != current.ID || previous.Revision != current.Revision || next == ([32]byte{}) {
			return false, tokenrefresh.ErrInvalid
		}
		absolute = current.AbsoluteExpiresAt
		previousIdle = current.IdleExpiresAt
		if err := check(); err != nil {
			return false, err
		}
		if current.Revision >= uint64(s.config.MaxRotations) {
			if err := deleteFamily(ctx, tx, current.ID, scope); err != nil {
				return false, err
			}
			return true, tokenrefresh.ErrInvalid
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM refresh_digests_v2 WHERE digest=?", next[:]).Scan(&count); err != nil {
			return false, err
		}
		if count != 0 {
			return false, tokenrefresh.ErrUnavailable
		}
		current.Current, current.IdleExpiresAt = next, idleExpiry
		current.Revision++
		data, err := encodeSession(current)
		if err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO refresh_digests_v2(digest,family) VALUES(?,?)", next[:], current.ID); err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE refresh_families_v2 SET payload=?,expires_at=? WHERE id=? AND namespace=? AND generation=?", data, idleExpiry, current.ID, scope.Namespace, scope.ID)
		return err == nil, err
	})
}

// Revoke accepts a current or spent digest and is idempotent for unknown tokens.
func (s *Store) revoke(ctx context.Context, scope tokenrefresh.Generation, digest [32]byte, binding tokenrefresh.Binding) error {
	return s.transactScope(ctx, scope, nil, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		session, err := loadDigest(ctx, tx, digest, scope)
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if session.Binding != binding {
			return true, nil
		}
		err = deleteFamily(ctx, tx, session.ID, scope)
		return err == nil, err
	})
}

// ValidateSession checks a trusted session reference without rotating it or
// touching replay history. The session ID alone is not authentication evidence.
func (s *Store) validateSession(ctx context.Context, scope tokenrefresh.Generation, id string, binding tokenrefresh.Binding) error {
	var session tokenrefresh.Session
	check := func() error {
		if s.now().Unix() >= session.IdleExpiresAt {
			return tokenrefresh.ErrInvalid
		}
		return nil
	}
	return s.transactScope(ctx, scope, check, func(ctx context.Context, tx *sql.Tx) (bool, error) {
		var data []byte
		var expiry int64
		if err := tx.QueryRowContext(ctx, "SELECT payload,expires_at FROM refresh_families_v2 WHERE id=? AND namespace=? AND generation=?", id, scope.Namespace, scope.ID).Scan(&data, &expiry); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, tokenrefresh.ErrInvalid
			}
			return false, err
		}
		var err error
		session, err = decodeSession(data)
		if err != nil {
			return false, err
		}
		if session.ID != id || bindingScope(session.Binding) != scope || session.IdleExpiresAt != expiry {
			return false, tokenrefresh.ErrUnavailable
		}
		if session.Binding != binding {
			return false, tokenrefresh.ErrInvalid
		}
		return true, check()
	})
}
