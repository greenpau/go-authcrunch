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
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	notifications "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	"go.uber.org/zap"
)

// ErrInvalid rejects malformed configuration or enrollment input.
var ErrInvalid = errors.New("invalid SQLite registration input")

// ErrDenied withholds confirmation for missing, expired, locked or spent entries.
var ErrDenied = errors.New("SQLite registration confirmation denied")

// ErrConflict refuses to replace an existing registration identifier.
var ErrConflict = errors.New("SQLite registration already exists")

// ErrFull refuses admission after the lifetime record bound is reached.
var ErrFull = errors.New("SQLite registration capacity reached")

// ErrUnsupported rejects operations outside email-confirmed enrollment.
var ErrUnsupported = errors.New("unsupported SQLite registration operation")

// ErrUnavailable indicates a storage or dependent-backend failure.
var ErrUnavailable = sqlitedb.ErrUnavailable

// ErrCommitUncertain means a mutation needs reconciliation before retry.
var ErrCommitUncertain = sqlitedb.ErrCommitUncertain

// Workflow owns pending enrollment storage. Injected accounts and outbox stay caller-owned.
type Workflow struct {
	config   Config
	db       *sqlitedb.Database
	store    *accounts.Store
	outbox   *notifications.Outbox
	renderer *registry.LocalUserRegistryProvider
	binding  [32]byte
}
type pending struct {
	username, email, enrollment, state string
	password, code                     []byte
	expires                            int64
	attempts                           int
}

// New opens a workflow bound to an existing SQLite identity store and outbox.
// Successful confirmation immediately creates an enabled authp/user account.
func New(ctx context.Context, config *Config, store *accounts.Store, outbox *notifications.Outbox) (*Workflow, error) {
	if config == nil || store == nil || outbox == nil {
		return nil, ErrInvalid
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if store.GetName() != c.IdentityStore || store.GetRealm() != c.Realm || !store.Configured() || outbox.Validate() != nil {
		return nil, ErrInvalid
	}
	messagingConfig := &messaging.Config{}
	if err := messagingConfig.AddProvider(c.EmailProvider, outbox); err != nil {
		return nil, ErrInvalid
	}
	if err := messagingConfig.Validate(); err != nil {
		return nil, ErrInvalid
	}
	renderer := &registry.LocalUserRegistryProvider{EmailProviderName: c.EmailProvider}
	if err := renderer.SetMessaging(messagingConfig); err != nil {
		return nil, ErrInvalid
	}
	db, err := sqlitedb.Open(ctx, c.Path, c.Timeout, 1094931287, map[string]string{"registrations": "CREATE TABLE registrations (id BLOB PRIMARY KEY, binding BLOB NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, enrollment TEXT NOT NULL, password BLOB, code BLOB, expires INTEGER NOT NULL, attempts INTEGER NOT NULL, state TEXT NOT NULL)"})
	if err != nil {
		return nil, err
	}
	binding, _ := json.Marshal([]string{c.Name, c.IdentityStore, c.Realm, c.EmailProvider, c.PublicOrigin, c.BasePath})
	return &Workflow{config: c, db: db, store: store, outbox: outbox, renderer: renderer, binding: sha256.Sum256(binding)}, nil
}
func registrationID(id string) bool { return matches(`^[A-Za-z0-9]{64,96}$`, id) }
func (w *Workflow) read(ctx context.Context, tx *sql.Tx, id string) (pending, error) {
	var p pending
	digest := sha256.Sum256([]byte(id))
	err := tx.QueryRowContext(ctx, "SELECT username,email,enrollment,password,code,expires,attempts,state FROM registrations WHERE id=? AND binding=?", digest[:], w.binding[:]).Scan(&p.username, &p.email, &p.enrollment, &p.password, &p.code, &p.expires, &p.attempts, &p.state)
	if errors.Is(err, sql.ErrNoRows) {
		return pending{}, ErrDenied
	}
	return p, err
}
func live(p pending) bool {
	return p.state == "pending" && p.expires > time.Now().Unix() && p.attempts < 5
}

// AddRegistrationEntry persists a bcrypt hash and code digest, never plaintext credentials.
// Existing IDs are immutable. The legacy interface uses the configured DB timeout.
func (w *Workflow) AddRegistrationEntry(id string, data map[string]string) error {
	if w == nil || w.db == nil {
		return ErrUnavailable
	}
	if !registrationID(id) || data["realm_name"] != w.config.Realm || !matches(`^[a-z0-9]{3,25}$`, data["username"]) || data["username"] == "nobody" || !matches(`^[A-Za-z0-9]{6,8}$`, data["registration_code"]) || identity.IsPasswordHashImport(data["password"]) {
		return ErrInvalid
	}
	email := strings.ToLower(data["email"])
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || !sqlitedb.ValidText(email, 254) {
		return ErrInvalid
	}
	hash, err := accounts.HashPassword(data["password"])
	if err != nil {
		return ErrInvalid
	}
	digest := sha256.Sum256([]byte(id))
	code := sha256.Sum256([]byte(data["registration_code"]))
	return w.db.Write(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM registrations WHERE id=?", digest[:]).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM registrations").Scan(&count); err != nil {
			return err
		}
		if count >= 10000 {
			return ErrFull
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO registrations VALUES(?,?,?,?,?,?,?,?,0,'pending')", digest[:], w.binding[:], data["username"], email, uuid.NewString(), hash, code[:], time.Now().Add(45*time.Minute).Unix())
		return err
	})
}

// GetRegistrationEntry returns pending public metadata, never codes or password hashes.
func (w *Workflow) GetRegistrationEntry(id string) (map[string]string, error) {
	if w == nil || w.db == nil {
		return nil, ErrUnavailable
	}
	if !registrationID(id) {
		return nil, ErrDenied
	}
	var result map[string]string
	err := w.db.Read(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		p, err := w.read(ctx, tx, id)
		if err != nil {
			return err
		}
		if !live(p) {
			return ErrDenied
		}
		result = map[string]string{"username": p.username, "email": p.email, "realm_name": w.config.Realm}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteRegistrationEntry cancels pending enrollment without erasing replay history.
func (w *Workflow) DeleteRegistrationEntry(id string) error {
	if w == nil || w.db == nil {
		return ErrUnavailable
	}
	if !registrationID(id) {
		return ErrDenied
	}
	digest := sha256.Sum256([]byte(id))
	return w.db.Write(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE registrations SET state='cancelled',password=NULL,code=NULL WHERE id=? AND binding=? AND state='pending'", digest[:], w.binding[:])
		return err
	})
}

// ConfirmRegistration consumes the code once and creates an enabled account.
// The account database commits first using the durable enrollment UUID. If this
// database's commit fails, retry with a fresh handle: identical enrollment cannot
// duplicate, modify or resurrect an account. No cross-file atomicity is promised.
func (w *Workflow) ConfirmRegistration(ctx context.Context, id, code string) error {
	if w == nil || w.db == nil {
		return ErrUnavailable
	}
	if !registrationID(id) || len(code) > 128 {
		return ErrDenied
	}
	digest := sha256.Sum256([]byte(id))
	candidate := sha256.Sum256([]byte(code))
	denied := false
	accountCommitted, accountUncertain := false, false
	err := w.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		p, err := w.read(ctx, tx, id)
		if err != nil {
			return err
		}
		if !live(p) {
			return ErrDenied
		}
		if subtle.ConstantTimeCompare(p.code, candidate[:]) != 1 {
			denied = true
			_, err := tx.ExecContext(ctx, "UPDATE registrations SET attempts=attempts+1 WHERE id=?", digest[:])
			return err
		}
		if _, err := w.store.CreateEnrollment(ctx, p.enrollment, &accounts.Account{Username: p.username, Email: p.email, Roles: []string{"authp/user"}}, p.password); err != nil {
			accountUncertain = errors.Is(err, accounts.ErrCommitUncertain)
			return ErrUnavailable
		}
		accountCommitted = true
		_, err = tx.ExecContext(ctx, "UPDATE registrations SET state='confirmed',password=NULL,code=NULL WHERE id=?", digest[:])
		return err
	})
	if err != nil {
		if accountCommitted || accountUncertain {
			return errors.Join(ErrCommitUncertain, err)
		}
		return err
	}
	if denied {
		return ErrDenied
	}
	return nil
}

// Notify queues a confirmation using the configured origin, never request Host.
func (w *Workflow) Notify(data map[string]string) error {
	if w == nil || w.db == nil {
		return ErrUnavailable
	}
	if data["template"] != "registration_confirmation" || !registrationID(data["registration_id"]) {
		return ErrUnsupported
	}
	safe := maps.Clone(data)
	err := w.db.Read(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		p, err := w.read(ctx, tx, data["registration_id"])
		if err != nil {
			return err
		}
		code := sha256.Sum256([]byte(data["registration_code"]))
		if !live(p) || subtle.ConstantTimeCompare(p.code, code[:]) != 1 {
			return ErrDenied
		}
		safe["username"] = p.username
		safe["email"] = p.email
		return nil
	})
	if err != nil {
		return err
	}
	safe["realm_name"] = w.config.Realm
	safe["registration_url"] = w.config.PublicOrigin + strings.TrimSuffix(w.config.BasePath, "/") + "/register"
	return w.renderer.Notify(safe)
}

// Validate checks immutable declarative configuration and dependency binding.
func (w *Workflow) Validate() error {
	if w == nil || w.store == nil || w.outbox == nil {
		return ErrInvalid
	}
	c := w.config
	return c.Validate()
}

// Activate validates an already opened workflow; it starts no workers.
func (w *Workflow) Activate(*zap.Logger) error { return w.Validate() }

// AsMap returns identifiers without paths, origins, codes or credentials.
func (w *Workflow) AsMap() map[string]any {
	if w == nil {
		return nil
	}
	return map[string]any{"name": w.config.Name, "kind": w.Kind(), "identity_store": w.config.IdentityStore, "realm": w.config.Realm}
}

// Kind identifies durable email confirmation.
func (w *Workflow) Kind() string { return "sqlite" }

// GetName returns the configured registry name.
func (w *Workflow) GetName() string { return w.config.Name }

// GetIdentityStoreName returns the immutable enrollment destination.
func (w *Workflow) GetIdentityStoreName() string { return w.config.IdentityStore }

// GetRealmName returns the bound account realm.
func (w *Workflow) GetRealmName() string { return w.config.Realm }

// SetRealmName cannot rebind an opened workflow. New validates the store's realm.
func (w *Workflow) SetRealmName(string) {}

// GetEmailProvider returns the constructor's outbox binding name.
func (w *Workflow) GetEmailProvider() string { return w.config.EmailProvider }

// SetMessaging validates the existing binding without changing the opened workflow.
func (w *Workflow) SetMessaging(c *messaging.Config) error {
	if c == nil {
		return ErrInvalid
	}
	p, ok := c.ExtractProvider(w.config.EmailProvider).(*notifications.Outbox)
	if !ok || p != w.outbox {
		return ErrInvalid
	}
	return nil
}

// SetCredentials accepts no transport credentials; the outbox worker owns them.
func (w *Workflow) SetCredentials(c *credentials.Config) error {
	if c != nil {
		return ErrUnsupported
	}
	return nil
}

// AddUser rejects the legacy non-transactional enrollment path.
func (w *Workflow) AddUser(*requests.Request) error { return ErrUnsupported }

// GetUsernamePolicyRegex returns the public registration username grammar.
func (w *Workflow) GetUsernamePolicyRegex() string { return `[a-z0-9]{3,25}` }

// GetUsernamePolicySummary describes the accepted username.
func (w *Workflow) GetUsernamePolicySummary() string { return "3–25 lowercase letters or digits" }

// GetPasswordPolicyRegex supplies a browser hint; backend byte limits remain authoritative.
func (w *Workflow) GetPasswordPolicyRegex() string { return `.{12,72}` }

// GetPasswordPolicySummary describes backend password limits.
func (w *Workflow) GetPasswordPolicySummary() string { return "12–72 UTF-8 bytes" }

// GetTitle returns the registration page title.
func (w *Workflow) GetTitle() string { return "Create an account" }

// GetCode returns no shared enrollment invitation code.
func (w *Workflow) GetCode() string { return "" }

// GetRequireAcceptTerms reports the fixed reference policy.
func (w *Workflow) GetRequireAcceptTerms() bool { return false }

// GetTermsConditionsLink uses the portal's default link.
func (w *Workflow) GetTermsConditionsLink() string { return "" }

// GetPrivacyPolicyLink uses the portal's default link.
func (w *Workflow) GetPrivacyPolicyLink() string { return "" }

// GetRequireDomainMX avoids network-dependent enrollment validation.
func (w *Workflow) GetRequireDomainMX() bool { return false }

// GetDomainRestrictions reports the open reference enrollment policy.
func (w *Workflow) GetDomainRestrictions() []string { return nil }

// GetAdminEmails returns no administrators; email confirmation activates the account.
func (w *Workflow) GetAdminEmails() []string { return nil }

// Close closes only pending storage, retaining supplied account/outbox ownership.
func (w *Workflow) Close() error {
	if w == nil {
		return nil
	}
	return w.db.Close()
}

var _ registry.Provider = (*Workflow)(nil)
var _ registry.ConfirmationProvider = (*Workflow)(nil)
