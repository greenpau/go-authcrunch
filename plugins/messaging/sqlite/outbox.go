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

// Package sqlite queues notifications for a caller-owned delivery worker.
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

// ErrInvalid indicates invalid message input or configuration.
var ErrInvalid = errors.New("invalid SQLite outbox input")

// ErrFull refuses admission without deleting queued work.
var ErrFull = errors.New("SQLite outbox is full")

// ErrEmpty means no message is presently available for a worker.
var ErrEmpty = errors.New("SQLite outbox has no available message")

// ErrLease rejects missing, stale, expired or wrong worker acknowledgements.
var ErrLease = errors.New("SQLite outbox lease invalid")

// ErrUnavailable indicates current queue state could not be read or written.
var ErrUnavailable = sqlitedb.ErrUnavailable

// ErrCommitUncertain requires reconciliation before retrying a mutation.
var ErrCommitUncertain = sqlitedb.ErrCommitUncertain

// Message is detached worker data. Lease is a short-lived acknowledgement secret.
type Message struct {
	ID         int64    `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Subject    string   `json:"subject,omitempty" xml:"subject,omitempty" yaml:"subject,omitempty"`
	Body       string   `json:"body,omitempty" xml:"body,omitempty" yaml:"body,omitempty"`
	Recipients []string `json:"recipients,omitempty" xml:"recipients,omitempty" yaml:"recipients,omitempty"`
	CreatedAt  int64    `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Lease      string   `json:"-" xml:"-" yaml:"-"`
}

// Outbox owns a queue handle. It does not start workers or deliver SMTP traffic.
type Outbox struct {
	config Config
	db     *sqlitedb.Database
}

// New opens a durable named queue using the pure-Go SQLite driver.
func New(ctx context.Context, config *Config) (*Outbox, error) {
	if config == nil {
		return nil, ErrInvalid
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	db, err := sqlitedb.Open(ctx, c.Path, c.Timeout, 1094931286, map[string]string{"messages": "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, queue TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=65536), created INTEGER NOT NULL, lease BLOB, leased_until INTEGER NOT NULL)"})
	if err != nil {
		return nil, err
	}
	return &Outbox{config: c, db: db}, nil
}

// Validate checks configuration without opening files or mutating the caller.
func (o *Outbox) Validate() error {
	if o == nil {
		return ErrInvalid
	}
	c := o.config
	return c.Validate()
}

// Kind identifies durable queue acceptance, not final message delivery.
func (o *Outbox) Kind() string { return "sqlite" }

// AsMap exposes safe metadata without message bodies, credentials or file paths.
func (o *Outbox) AsMap() map[string]any {
	if o == nil {
		return nil
	}
	return map[string]any{"name": o.config.Name, "kind": o.Kind()}
}
func validateMessage(m *Message) error {
	if m == nil || !sqlitedb.ValidText(m.Subject, 512) || m.Body == "" || len(m.Body) > 60000 || !utf8.ValidString(m.Body) || strings.ContainsRune(m.Body, 0) || len(m.Recipients) == 0 || len(m.Recipients) > 16 {
		return ErrInvalid
	}
	for _, recipient := range m.Recipients {
		if !sqlitedb.ValidText(recipient, 320) {
			return ErrInvalid
		}
		a, err := mail.ParseAddress(recipient)
		if err != nil || a.Address != recipient {
			return ErrInvalid
		}
	}
	return nil
}

// Send commits a queued message; the legacy interface uses the configured timeout.
func (o *Outbox) Send(input *messaging.SendInput) error {
	return o.SendContext(context.Background(), input)
}

// SendContext returns success only after durable local acceptance. Retries after
// uncertain acceptance can duplicate messages; callers must reconcile that case.
func (o *Outbox) SendContext(ctx context.Context, input *messaging.SendInput) error {
	if o == nil || o.db == nil {
		return ErrUnavailable
	}
	if input == nil || input.Credentials != nil {
		return ErrInvalid
	}
	message := &Message{Subject: input.Subject, Body: input.Body, Recipients: append([]string(nil), input.Recipients...)}
	if err := validateMessage(message); err != nil {
		return err
	}
	data, err := json.Marshal(message)
	if err != nil || len(data) > 65536 {
		return ErrInvalid
	}
	return o.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM messages").Scan(&count); err != nil {
			return err
		}
		if count >= 1000 {
			return ErrFull
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO messages(queue,payload,created,leased_until) VALUES(?,?,?,0)", o.config.Name, data, time.Now().Unix())
		return err
	})
}

// Claim leases the oldest available message for one minute. A crash or missing
// acknowledgement allows redelivery after expiry: workers must handle duplicates.
func (o *Outbox) Claim(ctx context.Context) (*Message, error) {
	if o == nil || o.db == nil {
		return nil, ErrUnavailable
	}
	var message Message
	lease := rand.Text()
	digest := sha256.Sum256([]byte(lease))
	err := o.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var id, created int64
		var data []byte
		now := time.Now().Unix()
		err := tx.QueryRowContext(ctx, "SELECT id,payload,created FROM messages WHERE queue=? AND leased_until<=? ORDER BY id LIMIT 1", o.config.Name, now).Scan(&id, &data, &created)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEmpty
		}
		if err != nil {
			return err
		}
		if len(data) > 65536 || json.Unmarshal(data, &message) != nil || validateMessage(&message) != nil {
			return ErrUnavailable
		}
		message.ID = id
		message.CreatedAt = created
		message.Lease = lease
		_, err = tx.ExecContext(ctx, "UPDATE messages SET lease=?,leased_until=? WHERE id=?", digest[:], now+60, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &message, nil
}

// Acknowledge removes work only for its current unexpired lease. Call after
// delivery, not before; a crash between delivery and acknowledgement can replay.
func (o *Outbox) Acknowledge(ctx context.Context, id int64, lease string) error {
	return o.finish(ctx, id, lease, true)
}

// Release immediately makes a leased message available to another attempt.
func (o *Outbox) Release(ctx context.Context, id int64, lease string) error {
	return o.finish(ctx, id, lease, false)
}
func (o *Outbox) finish(ctx context.Context, id int64, lease string, remove bool) error {
	if o == nil || o.db == nil {
		return ErrUnavailable
	}
	if id <= 0 || len(lease) < 26 || len(lease) > 128 {
		return ErrLease
	}
	digest := sha256.Sum256([]byte(lease))
	return o.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		statement := "UPDATE messages SET lease=NULL,leased_until=0 WHERE queue=? AND id=? AND lease=? AND leased_until>?"
		if remove {
			statement = "DELETE FROM messages WHERE queue=? AND id=? AND lease=? AND leased_until>?"
		}
		result, err := tx.ExecContext(ctx, statement, o.config.Name, id, digest[:], time.Now().Unix())
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrLease
		}
		return nil
	})
}

// Close drains the handle without deleting queued messages or active leases.
func (o *Outbox) Close() error {
	if o == nil {
		return nil
	}
	return o.db.Close()
}

var _ messaging.Provider = (*Outbox)(nil)
