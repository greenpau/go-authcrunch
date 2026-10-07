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
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
)

// ErrNotFound indicates an absent record or an absent top-level key.
var ErrNotFound = errors.New("secret not found")

// ErrInvalid indicates an unsupported or oversized JSON record/value.
var ErrInvalid = errors.New("invalid secret record")

// ErrUnavailable indicates that the private backend could not be accessed.
var ErrUnavailable = sqlitedb.ErrUnavailable

// ErrCommitUncertain means a write may have committed; reconcile before retry.
var ErrCommitUncertain = sqlitedb.ErrCommitUncertain

// Client is a context-aware reader and trusted provisioner for one bound record.
// Each lookup reads a fresh snapshot. Hosts own Close and configuration adoption.
type Client struct {
	config Config
	db     *sqlitedb.Database
}

// New opens a dedicated secrets database. It does not require an existing record.
func New(ctx context.Context, config *Config) (*Client, error) {
	if config == nil {
		return nil, ErrInvalid
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	db, err := sqlitedb.Open(ctx, c.Path, c.Timeout, 1094931283, map[string]string{
		"secrets": "CREATE TABLE secrets (name TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=65536))",
	})
	if err != nil {
		return nil, err
	}
	return &Client{config: c, db: db}, nil
}

// GetConfig returns detached metadata, excluding values and filesystem paths.
func (c *Client) GetConfig() map[string]any {
	if c == nil {
		return nil
	}
	return map[string]any{"name": c.config.Name, "kind": "sqlite", "record": c.config.Record}
}

// Put atomically replaces the bound record. Provisioning is a trusted host API,
// not a public HTTP endpoint. Values must be JSON; numbers read as json.Number.
// Records are plaintext private data, limited to 64 KiB and 128 top-level keys.
func (c *Client) Put(ctx context.Context, values map[string]any) error {
	if c == nil {
		return ErrUnavailable
	}
	if len(values) == 0 || len(values) > 128 {
		return ErrInvalid
	}
	for key := range values {
		if !sqlitedb.ValidText(key, 256) {
			return ErrInvalid
		}
	}
	data, err := json.Marshal(values)
	if err != nil || len(data) > 65536 {
		return ErrInvalid
	}
	return c.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM secrets WHERE name<>?", c.config.Record).Scan(&count); err != nil {
			return err
		}
		if count >= 1024 {
			return ErrUnavailable
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO secrets(name,payload) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload", c.config.Record, data)
		return err
	})
}

// GetSecrets returns a detached coherent record. Nested numbers use json.Number;
// a missing record and an unavailable backend never produce fallback values.
func (c *Client) GetSecrets(ctx context.Context) (map[string]any, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	var data []byte
	err := c.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT payload FROM secrets WHERE name=?", c.config.Record).Scan(&data)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 65536 || !json.Valid(data) {
		return nil, ErrUnavailable
	}
	var values map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&values) != nil || len(values) == 0 || len(values) > 128 {
		return nil, ErrUnavailable
	}
	return values, nil
}

// GetSecret selects an exact top-level key; dots do not imply traversal.
func (c *Client) GetSecret(ctx context.Context, key string) (any, error) {
	if !sqlitedb.ValidText(key, 256) {
		return nil, ErrInvalid
	}
	values, err := c.GetSecrets(ctx)
	if err != nil {
		return nil, err
	}
	value, ok := values[key]
	if !ok {
		return nil, ErrNotFound
	}
	return value, nil
}

// GetString retrieves a required nonempty string without coercing other types.
func (c *Client) GetString(ctx context.Context, key string) (string, error) {
	value, err := c.GetSecret(ctx, key)
	if err != nil {
		return "", err
	}
	s, ok := value.(string)
	if !ok || s == "" {
		return "", ErrInvalid
	}
	return s, nil
}

// Delete atomically removes the bound record; an absent record is already deleted.
func (c *Client) Delete(ctx context.Context) error {
	if c == nil {
		return ErrUnavailable
	}
	return c.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM secrets WHERE name=?", c.config.Record)
		return err
	})
}

// Close releases this client's owned database handle, retaining stored records.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	return c.db.Close()
}
