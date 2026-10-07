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

// Package sqlite implements fresh API-key verification against private SQLite.
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"
	"time"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
)

// ErrInvalid indicates invalid trusted provisioning input.
var ErrInvalid = errors.New("invalid SQLite credential input")

// ErrDenied does not distinguish absent, expired, revoked or wrong-realm keys.
var ErrDenied = errors.New("SQLite credential authentication denied")

// ErrUnavailable indicates that current credential state could not be read.
var ErrUnavailable = sqlitedb.ErrUnavailable

// ErrCommitUncertain requires reconciliation before retrying a mutation.
var ErrCommitUncertain = sqlitedb.ErrCommitUncertain

// Authenticator owns a realm-bound database handle; the embedding host owns Close.
type Authenticator struct {
	config Config
	db     *sqlitedb.Database
}

// New opens a private credential database without provisioning any credentials.
func New(ctx context.Context, config *Config) (*Authenticator, error) {
	if config == nil {
		return nil, sqlitedb.ErrConfig
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	db, err := sqlitedb.Open(ctx, c.Path, c.Timeout, 1094931284, map[string]string{
		"api_keys": "CREATE TABLE api_keys (digest BLOB PRIMARY KEY NOT NULL, realm TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL, roles BLOB NOT NULL, expires INTEGER NOT NULL)",
	})
	if err != nil {
		return nil, err
	}
	return &Authenticator{config: c, db: db}, nil
}

// GetName selects this authenticator in the gatekeeper's portal binding.
func (a *Authenticator) GetName() string {
	if a == nil {
		return ""
	}
	return a.config.Name
}

// RequireFreshAuthentication prevents cached credentials from bypassing revocation.
func (a *Authenticator) RequireFreshAuthentication() bool { return true }

// GetConfig exposes identifiers without keys, payloads or database paths.
func (a *Authenticator) GetConfig() map[string]any {
	if a == nil {
		return nil
	}
	return map[string]any{"name": a.config.Name, "kind": "sqlite", "realm": a.config.Realm}
}

// Issue creates a 256-bit key, returning plaintext exactly once after commit.
// Subjects, email and roles are supplied only by trusted provisioning code.
// The expiry must lie within the next 30 days. Expired keys are pruned on issue.
func (a *Authenticator) Issue(ctx context.Context, subject, email string, roles []string, expires time.Time) (string, error) {
	if a == nil || a.db == nil {
		return "", ErrUnavailable
	}
	if !sqlitedb.ValidText(subject, 256) || !sqlitedb.ValidText(email, 320) || len(roles) == 0 || len(roles) > 32 {
		return "", ErrInvalid
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", ErrInvalid
	}
	for _, role := range roles {
		if !sqlitedb.ValidText(role, 128) {
			return "", ErrInvalid
		}
	}
	now := time.Now()
	if expires.Unix() <= now.Unix() || expires.After(now.Add(30*24*time.Hour)) {
		return "", ErrInvalid
	}
	payload, err := json.Marshal(roles)
	if err != nil {
		return "", ErrInvalid
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", ErrUnavailable
	}
	key := base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(key))
	err = a.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM api_keys WHERE expires<=?", now.Unix()); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM api_keys").Scan(&count); err != nil {
			return err
		}
		if count >= 10000 {
			return ErrInvalid
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO api_keys VALUES(?,?,?,?,?,?)", digest[:], a.config.Realm, subject, email, payload, expires.Unix())
		return err
	})
	if err != nil {
		return "", err
	}
	return key, nil
}

// Revoke atomically removes a bound-realm key; absence is an idempotent success.
func (a *Authenticator) Revoke(ctx context.Context, key string) error {
	if a == nil || a.db == nil {
		return ErrUnavailable
	}
	if !validKey(key) {
		return ErrInvalid
	}
	digest := sha256.Sum256([]byte(key))
	return a.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM api_keys WHERE realm=? AND digest=?", a.config.Realm, digest[:])
		return err
	})
}
func validKey(key string) bool {
	if len(key) != 43 {
		return false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(key)
	return err == nil && len(data) == 32
}

// BasicAuth always rejects unsupported password authentication.
func (a *Authenticator) BasicAuth(r *authproxy.Request) error {
	return a.BasicAuthContext(context.Background(), r)
}

// BasicAuthContext clears stale responses and rejects unsupported credentials.
func (a *Authenticator) BasicAuthContext(_ context.Context, r *authproxy.Request) error {
	if r != nil {
		r.Response = authproxy.Response{}
	}
	return ErrDenied
}

// APIKeyAuth supports the legacy interface with the configured operation timeout.
func (a *Authenticator) APIKeyAuth(r *authproxy.Request) error {
	return a.APIKeyAuthContext(context.Background(), r)
}

// APIKeyAuthContext binds the key to this realm and publishes only fresh claims.
func (a *Authenticator) APIKeyAuthContext(ctx context.Context, r *authproxy.Request) error {
	if r == nil {
		return ErrDenied
	}
	r.Response = authproxy.Response{}
	if a == nil || a.db == nil {
		return ErrUnavailable
	}
	if r.Realm != a.config.Realm || !validKey(r.Secret) {
		return ErrDenied
	}
	digest := sha256.Sum256([]byte(r.Secret))
	var subject, email string
	var roles []string
	var expiry int64
	err := a.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var data []byte
		err := tx.QueryRowContext(ctx, "SELECT subject,email,roles,expires FROM api_keys WHERE realm=? AND digest=?", a.config.Realm, digest[:]).Scan(&subject, &email, &data, &expiry)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
		if err != nil {
			return err
		}
		if expiry <= time.Now().Unix() {
			return ErrDenied
		}
		if len(data) > 8192 || json.Unmarshal(data, &roles) != nil || len(roles) == 0 || len(roles) > 32 {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return err
	}
	now := time.Now()
	if expiry <= now.Unix() {
		return ErrDenied
	}
	data, err := json.Marshal(map[string]any{"sub": subject, "email": email, "roles": roles, "origin": a.config.Realm, "iat": now.Unix(), "exp": min(expiry, now.Add(time.Minute).Unix()), "amr": []string{"api_key"}})
	if err != nil {
		return ErrUnavailable
	}
	r.Response = authproxy.Response{Name: "access_token", Payload: string(data), IsPlainPayload: true}
	return nil
}

// Close drains connections without deleting credential state.
func (a *Authenticator) Close() error {
	if a == nil {
		return nil
	}
	return a.db.Close()
}

var _ authproxy.Authenticator = (*Authenticator)(nil)
var _ authproxy.ContextAuthenticator = (*Authenticator)(nil)
var _ authproxy.FreshAuthenticator = (*Authenticator)(nil)
