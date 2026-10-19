// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"encoding/json"
	"errors"
	"time"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

// Store owns a private connection. Independent clients coordinate via SQLite
// transactions. Close preserves records and drains this connection only.
type Store struct {
	db       *sqlitedb.Database
	capacity int
}

var _ oauth.LoginStore = (*Store)(nil)

const maxRecordSize = 65536

// A pending record must remain readable after adding any valid claim. JSON can
// expand each claim byte to six bytes, plus the initially omitted field itself.
const maxClaimGrowth = len(`,"claim":""`) + 128*6

var schema = map[string]string{
	"oauth_logins": "CREATE TABLE oauth_logins(namespace TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(namespace,state))",
	"oauth_limits": "CREATE TABLE oauth_limits(id INTEGER PRIMARY KEY CHECK(id=1), capacity INTEGER NOT NULL)",
}

// New validates a detached configuration and opens the database. The caller
// owns Close. Requires a trusted private directory and reliable local SQLite
// locking/sync; network filesystems and replicated file copies are unsupported.
func New(ctx context.Context, config *Config) (*Store, error) {
	if config == nil {
		return nil, oauth.ErrLoginUnavailable
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	db, err := sqlitedb.OpenExclusive(ctx, c.Path, c.Timeout, 0x41554f4c, schema)
	if err != nil {
		return nil, oauth.ErrLoginUnavailable
	}
	s := &Store{db: db, capacity: c.Capacity}
	err = db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO oauth_limits(id,capacity) VALUES(1,?)", c.Capacity); err != nil {
			return err
		}
		var capacity int
		if err := tx.QueryRowContext(ctx, "SELECT capacity FROM oauth_limits WHERE id=1").Scan(&capacity); err != nil {
			return err
		}
		if capacity != c.Capacity {
			return oauth.ErrLoginUnavailable
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, oauth.ErrLoginUnavailable
	}
	return s, nil
}

func validKey(namespace, state string) bool {
	return (namespace == "" || sqlitedb.ValidText(namespace, 512)) && sqlitedb.ValidText(state, 128)
}
func (s *Store) available() bool { return s != nil && s.db != nil }
func safe(err error) error {
	if err == nil || errors.Is(err, oauth.ErrLoginInvalid) || errors.Is(err, oauth.ErrLoginCapacity) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return oauth.ErrLoginUnavailable
}
func load(ctx context.Context, tx *sql.Tx, namespace, state string) (oauth.LoginTransaction, error) {
	var data []byte
	err := tx.QueryRowContext(ctx, "SELECT CASE WHEN length(data)<=? THEN data ELSE NULL END FROM oauth_logins WHERE namespace=? AND state=?", maxRecordSize, namespace, state).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	var result oauth.LoginTransaction
	if json.Unmarshal(data, &result) != nil || result.State != state {
		return oauth.LoginTransaction{}, oauth.ErrLoginUnavailable
	}
	if result.Validate(time.Now()) != nil {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	return result, nil
}

// Create commits a complete fresh transaction before the caller redirects.
func (s *Store) Create(ctx context.Context, namespace string, value oauth.LoginTransaction) error {
	if !s.available() {
		return oauth.ErrLoginUnavailable
	}
	if !validKey(namespace, value.State) || value.Claim != "" {
		return oauth.ErrLoginInvalid
	}
	return safe(s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		now := time.Now()
		if err := value.Validate(now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM oauth_logins WHERE expires<=?", now.Unix()); err != nil {
			return err
		}
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM oauth_logins WHERE namespace=? AND state=?", namespace, value.State).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			return oauth.ErrLoginInvalid
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM oauth_logins").Scan(&count); err != nil {
			return err
		}
		if count >= s.capacity {
			return oauth.ErrLoginCapacity
		}
		data, err := json.Marshal(value)
		if err != nil || len(data) > maxRecordSize-maxClaimGrowth {
			return oauth.ErrLoginInvalid
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO oauth_logins(namespace,state,expires,data) VALUES(?,?,?,?)", namespace, value.State, value.ExpiresAt, data)
		return err
	}))
}

// Claim checks the exact binding and publishes a single winner in one transaction.
func (s *Store) Claim(ctx context.Context, namespace, state string, binding oauth.LoginBinding, claim string) (oauth.LoginTransaction, error) {
	if !s.available() {
		return oauth.LoginTransaction{}, oauth.ErrLoginUnavailable
	}
	if !validKey(namespace, state) || !sqlitedb.ValidText(claim, 128) {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	var result oauth.LoginTransaction
	err := s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		value, err := load(ctx, tx, namespace, state)
		if err != nil {
			return err
		}
		if value.Claim != "" || !value.Binding.Matches(binding) {
			return oauth.ErrLoginInvalid
		}
		value.Claim = claim
		data, err := json.Marshal(value)
		if err != nil {
			return oauth.ErrLoginUnavailable
		}
		if _, err := tx.ExecContext(ctx, "UPDATE oauth_logins SET data=? WHERE namespace=? AND state=?", data, namespace, state); err != nil {
			return err
		}
		result = value
		return nil
	})
	if err != nil {
		return oauth.LoginTransaction{}, safe(err)
	}
	return result, nil
}

// Get retrieves unexpired evidence without changing its claim status.
func (s *Store) Get(ctx context.Context, namespace, state string) (oauth.LoginTransaction, error) {
	if !s.available() {
		return oauth.LoginTransaction{}, oauth.ErrLoginUnavailable
	}
	if !validKey(namespace, state) {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	var result oauth.LoginTransaction
	err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		result, err = load(ctx, tx, namespace, state)
		return err
	})
	if err != nil {
		return oauth.LoginTransaction{}, safe(err)
	}
	return result, nil
}

// Complete atomically consumes the exact claim, including the current expiry check.
func (s *Store) Complete(ctx context.Context, namespace, state, claim string) error {
	if !s.available() {
		return oauth.ErrLoginUnavailable
	}
	if !validKey(namespace, state) || !sqlitedb.ValidText(claim, 128) {
		return oauth.ErrLoginInvalid
	}
	return safe(s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		value, err := load(ctx, tx, namespace, state)
		if err != nil {
			return err
		}
		if value.Claim != claim {
			return oauth.ErrLoginInvalid
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM oauth_logins WHERE namespace=? AND state=?", namespace, state)
		return err
	}))
}

// Cancel removes only matching browser/callback evidence, including claimed work.
func (s *Store) Cancel(ctx context.Context, namespace, state string, binding oauth.LoginBinding) (bool, error) {
	if !s.available() {
		return false, oauth.ErrLoginUnavailable
	}
	if !validKey(namespace, state) {
		return false, nil
	}
	var canceled bool
	err := s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		value, err := load(ctx, tx, namespace, state)
		if errors.Is(err, oauth.ErrLoginInvalid) {
			return nil
		}
		if err != nil {
			return err
		}
		if !value.Binding.Matches(binding) {
			return nil
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM oauth_logins WHERE namespace=? AND state=?", namespace, state); err != nil {
			return err
		}
		canceled = true
		return nil
	})
	if err != nil {
		return false, safe(err)
	}
	return canceled, nil
}

// Close releases this client without deleting any other client's transactions.
func (s *Store) Close() error {
	if !s.available() {
		return nil
	}
	return safe(s.db.Close())
}
