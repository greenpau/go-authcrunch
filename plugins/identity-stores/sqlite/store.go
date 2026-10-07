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

// Package sqlite supplies a local password-only identity store.
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalid indicates invalid trusted account provisioning input.
var ErrInvalid = errors.New("invalid SQLite identity input")

// ErrDenied deliberately hides missing, disabled and invalid credentials.
var ErrDenied = errors.New("SQLite identity authentication denied")

// ErrConflict indicates a duplicate identity or conflicting enrollment.
var ErrConflict = errors.New("SQLite identity already exists")

// ErrUnsupported rejects operations outside this password-only reference.
var ErrUnsupported = errors.New("SQLite identity operation unsupported")

// ErrUnavailable indicates failure to retrieve current account state.
var ErrUnavailable = sqlitedb.ErrUnavailable

// ErrCommitUncertain requires reconciliation before retrying a mutation.
var ErrCommitUncertain = sqlitedb.ErrCommitUncertain

const dummyHash = "$2a$10$4xaU6KMqOfcdoZ5DhtIvKuePgy62eGAvZYYwGM/f5/fwB9ZXEAgtG"

// Account contains trusted account attributes, without credentials or runtime state.
type Account struct {
	Username string   `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Email    string   `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Name     string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Roles    []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
}

// Store owns a database connection and an instance-local authentication epoch.
type Store struct {
	config Config
	db     *sqlitedb.Database
	epoch  string
}
type accountRecord struct {
	id      string
	account Account
	hash    string
	version uint64
	enabled bool
}

// New opens a configured store. No default or administrative user is created.
func New(ctx context.Context, config *Config) (*Store, error) {
	if config == nil {
		return nil, sqlitedb.ErrConfig
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	db, err := sqlitedb.Open(ctx, c.Path, c.Timeout, 1094931285, map[string]string{
		"enrollments": "CREATE TABLE enrollments (id TEXT PRIMARY KEY NOT NULL, realm TEXT NOT NULL, account_id TEXT NOT NULL, fingerprint BLOB NOT NULL)",
		"accounts":    "CREATE TABLE accounts (id TEXT PRIMARY KEY NOT NULL, realm TEXT NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, name TEXT NOT NULL, roles BLOB NOT NULL, password TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), enrollment TEXT NOT NULL UNIQUE, UNIQUE(realm,username), UNIQUE(realm,email))",
	})
	if err != nil {
		return nil, err
	}
	return &Store{config: c, db: db, epoch: uuid.NewString()}, nil
}
func normalizeAccount(input *Account) (Account, error) {
	if input == nil {
		return Account{}, ErrInvalid
	}
	a := *input
	a.Roles = append([]string(nil), input.Roles...)
	a.Username = strings.ToLower(a.Username)
	a.Email = strings.ToLower(a.Email)
	valid, _ := regexp.MatchString(`^[a-z0-9][a-z0-9_.-]{2,63}$`, a.Username)
	if !valid || a.Username == "nobody" || !sqlitedb.ValidText(a.Email, 320) || (a.Name != "" && !sqlitedb.ValidText(a.Name, 256)) || len(a.Roles) == 0 || len(a.Roles) > 32 {
		return Account{}, ErrInvalid
	}
	address, err := mail.ParseAddress(a.Email)
	if err != nil || address.Address != a.Email {
		return Account{}, ErrInvalid
	}
	for _, role := range a.Roles {
		if !sqlitedb.ValidText(role, 128) {
			return Account{}, ErrInvalid
		}
	}
	return a, nil
}

// HashPassword hashes an exact plaintext password with the fixed bcrypt cost.
// It is also the registration workflow's public preparation boundary.
func HashPassword(password string) ([]byte, error) {
	if len(password) < 12 || len(password) > 72 || strings.TrimSpace(password) == "" || !utf8.ValidString(password) {
		return nil, ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, ErrInvalid
	}
	return hash, nil
}

// Create provisions a new password account; existing accounts are never overwritten.
func (s *Store) Create(ctx context.Context, a *Account, password string) (map[string]any, error) {
	if _, err := normalizeAccount(a); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	return s.CreateEnrollment(ctx, uuid.NewString(), a, hash)
}

// CreateEnrollment idempotently creates one immutable account for a trusted
// enrollment ID. The caller supplies a default-cost bcrypt hash, never a login
// candidate. A conflicting replay cannot change an account or its password.
func (s *Store) CreateEnrollment(ctx context.Context, enrollment string, input *Account, hash []byte) (map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	a, err := normalizeAccount(input)
	if err != nil {
		return nil, err
	}
	parsed, err := uuid.Parse(enrollment)
	if err != nil || parsed.String() != enrollment {
		return nil, ErrInvalid
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil || cost != bcrypt.DefaultCost || len(hash) != 60 {
		return nil, ErrInvalid
	}
	// A malformed salt/checksum must never become a cheap credential path.
	if err := bcrypt.CompareHashAndPassword(hash, []byte("synthetic-validation-only")); err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return nil, ErrInvalid
	}

	roles, _ := json.Marshal(a.Roles)
	canonical, _ := json.Marshal(a)
	fingerprint := sha256.Sum256(append(canonical, hash...))
	id := uuid.NewString()
	var result map[string]any
	err = s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var oldID, realm string
		var previous []byte
		err := tx.QueryRowContext(ctx, "SELECT account_id,realm,fingerprint FROM enrollments WHERE id=?", enrollment).Scan(&oldID, &realm, &previous)
		if err == nil {
			if realm != s.config.Realm || subtle.ConstantTimeCompare(previous, fingerprint[:]) != 1 {
				return ErrConflict
			}
			existing, err := s.lookup(ctx, tx, oldID, true)
			if err != nil {
				return err
			}
			result = accountMap(existing.id, existing.account)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE realm=? AND (username=? OR email=?)", s.config.Realm, a.Username, a.Email).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM enrollments").Scan(&count); err != nil {
			return err
		}
		if count >= 10000 {
			return ErrInvalid
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO accounts VALUES(?,?,?,?,?,?,?,1,1,?)", id, s.config.Realm, a.Username, a.Email, a.Name, roles, string(hash), enrollment); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO enrollments VALUES(?,?,?,?)", enrollment, s.config.Realm, id, fingerprint[:]); err != nil {
			return err
		}
		result = accountMap(id, a)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func accountMap(id string, a Account) map[string]any {
	return map[string]any{"id": id, "username": a.Username, "email": a.Email, "name": a.Name, "roles": append([]string(nil), a.Roles...)}
}
func (s *Store) lookup(ctx context.Context, tx *sql.Tx, selector string, byID bool) (accountRecord, error) {
	var r accountRecord
	var data []byte
	where := "(username=? OR email=?)"
	args := []any{s.config.Realm, strings.ToLower(selector), strings.ToLower(selector)}
	if byID {
		where = "id=?"
		args = []any{s.config.Realm, selector}
	}
	err := tx.QueryRowContext(ctx, "SELECT id,username,email,name,roles,password,version,enabled FROM accounts WHERE realm=? AND "+where, args...).Scan(&r.id, &r.account.Username, &r.account.Email, &r.account.Name, &data, &r.hash, &r.version, &r.enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrDenied
	}
	if err != nil {
		return r, err
	}
	if len(data) > 8192 || json.Unmarshal(data, &r.account.Roles) != nil {
		return r, ErrUnavailable
	}
	if _, err := normalizeAccount(&r.account); err != nil {
		return r, ErrUnavailable
	}
	return r, nil
}
func (s *Store) evidence(r accountRecord) requests.AuthenticationEvidence {
	return requests.AuthenticationEvidence{UserID: r.id, CredentialVersion: r.version, BackendVersion: s.epoch}
}
func fillRequest(r *requests.Request, a accountRecord) {
	r.User.Username = a.account.Username
	r.User.Email = a.account.Email
	r.User.FullName = a.account.Name
	r.User.Roles = append([]string(nil), a.account.Roles...)
	r.User.Challenges = []string{"password"}
	r.User.AuthMethods = []string{"password"}
	r.User.AuthChallengePolicy = false
}

// Request supports identification, password authentication and trusted creation.
// MFA, API keys, recovery and profile mutation are deliberately unsupported.
func (s *Store) Request(op operator.Type, r *requests.Request) error {
	if r == nil {
		return ErrInvalid
	}
	proof := r.Authentication
	r.Authentication = requests.AuthenticationEvidence{}
	r.Response = requests.Response{}
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	if r.Upstream.Realm != "" && r.Upstream.Realm != s.config.Realm {
		return ErrDenied
	}
	ctx := context.Background()
	if r.Upstream.Request != nil {
		ctx = r.Upstream.Request.Context()
	}
	switch op {
	case operator.AddUser:
		data, err := s.Create(ctx, &Account{Username: r.User.Username, Email: r.User.Email, Name: r.User.FullName, Roles: r.User.Roles}, r.User.Password)
		if err != nil {
			return err
		}
		r.Response.Payload = data
		return nil
	case operator.IdentifyUser, operator.Authenticate:
		r.User = requests.User{Username: r.User.Username, Password: r.User.Password}
		var found accountRecord
		err := s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
			current, err := s.lookup(ctx, tx, r.User.Username, false)
			if err != nil && !errors.Is(err, ErrDenied) {
				return err
			}
			if op == operator.IdentifyUser {
				if err != nil || !current.enabled {
					return nil
				}
				found = current
				return nil
			}
			hash := dummyHash
			real := err == nil && current.enabled
			if real {
				cost, costErr := bcrypt.Cost([]byte(current.hash))
				if costErr != nil || cost != bcrypt.DefaultCost {
					return ErrUnavailable
				}
				hash = current.hash
			}
			compare := bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.User.Password))
			if !real || compare != nil || r.User.Password == "" || len(r.User.Password) > 72 {
				return ErrDenied
			}
			if proof.UserID != "" && (proof.UserID != current.id || proof.CredentialVersion != current.version || proof.BackendVersion != s.epoch) {
				return ErrDenied
			}
			found = current
			return nil
		})
		if err != nil {
			return err
		}
		if found.id == "" {
			r.User.Username = "nobody"
			r.User.Email = "nobody@localhost"
			r.User.Roles = nil
			r.User.FullName = ""
			r.User.Challenges = []string{"password"}
			r.User.AuthMethods = []string{"password"}
			r.User.AuthChallengePolicy = false
			return nil
		}
		fillRequest(r, found)
		r.Authentication = s.evidence(found)
		if op == operator.Authenticate {
			r.Authentication.AuthenticatedAt = time.Now().Unix()
			r.Authentication.Method = "pwd"
			r.Response.Authenticated = true
		}
		r.Response.Code = 200
		return nil
	default:
		return ErrUnsupported
	}
}

// WithRefreshIdentity serializes account mutation against policy checks/signing.
// Callbacks must not reenter Store; publish tokens only after success.
func (s *Store) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	if apply == nil || proof.UserID == "" || proof.BackendVersion != s.epoch {
		return identity.ErrRefreshIdentityDenied
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		a, err := s.lookup(ctx, tx, proof.UserID, true)
		if errors.Is(err, ErrDenied) {
			return identity.ErrRefreshIdentityDenied
		}
		if err != nil {
			return err
		}
		if !a.enabled || a.version != proof.CredentialVersion {
			return identity.ErrRefreshIdentityDenied
		}
		return apply(identity.RefreshIdentity{Username: a.account.Username, Email: a.account.Email, Name: a.account.Name, Roles: append([]string(nil), a.account.Roles...), Challenges: []string{"password"}, AuthMethods: []string{"password"}})
	})
}

// SetPassword atomically replaces credentials and invalidates captured evidence.
func (s *Store) SetPassword(ctx context.Context, username, email, password string) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.mutate(ctx, username, email, func(ctx context.Context, tx *sql.Tx, a accountRecord) error {
		_, err := tx.ExecContext(ctx, "UPDATE accounts SET password=?,version=version+1 WHERE id=?", string(hash), a.id)
		return err
	})
}
func (s *Store) mutate(ctx context.Context, username, email string, apply func(context.Context, *sql.Tx, accountRecord) error) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	return s.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		a, err := s.lookup(ctx, tx, username, false)
		if err != nil {
			return err
		}
		if a.account.Username != strings.ToLower(username) || a.account.Email != strings.ToLower(email) {
			return ErrDenied
		}
		return apply(ctx, tx, a)
	})
}

// DeleteUser removes an exact username/email identity.
func (s *Store) DeleteUser(username, email string) error {
	return s.mutate(context.Background(), username, email, func(ctx context.Context, tx *sql.Tx, a accountRecord) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM accounts WHERE id=?", a.id)
		return err
	})
}

// DisableUser invalidates evidence even if the account was already disabled.
func (s *Store) DisableUser(username, email string) error {
	return s.setEnabled(username, email, false)
}

// EnableUser requires a fresh login after re-enabling an account.
func (s *Store) EnableUser(username, email string) error { return s.setEnabled(username, email, true) }
func (s *Store) setEnabled(username, email string, enabled bool) error {
	return s.mutate(context.Background(), username, email, func(ctx context.Context, tx *sql.Tx, a accountRecord) error {
		_, err := tx.ExecContext(ctx, "UPDATE accounts SET enabled=?,version=version+1 WHERE id=?", enabled, a.id)
		return err
	})
}

// FetchUserData returns detached non-secret attributes for an exact identity.
func (s *Store) FetchUserData(username, email string) (map[string]any, error) {
	var out map[string]any
	err := s.mutate(context.Background(), username, email, func(_ context.Context, _ *sql.Tx, a accountRecord) error {
		out = accountMap(a.id, a.account)
		out["disabled"] = !a.enabled
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetUsersMetadata lists bounded non-secret accounts in the selected realm.
func (s *Store) GetUsersMetadata(_ string) ([]map[string]any, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	var result []map[string]any
	err := s.db.Read(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT id,username,email,name,enabled FROM accounts WHERE realm=? ORDER BY username LIMIT 10001", s.config.Realm)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, username, email, name string
			var enabled bool
			if err := rows.Scan(&id, &username, &email, &name, &enabled); err != nil {
				return err
			}
			result = append(result, map[string]any{"id": id, "username": username, "email": email, "name": name, "disabled": !enabled})
			if len(result) > 10000 {
				return ErrUnavailable
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetMetadata exposes bounded capability metadata without account credentials.
func (s *Store) GetMetadata(_ string) (map[string]any, error) {
	if err := s.Configure(); err != nil {
		return nil, err
	}
	return map[string]any{"kind": "sqlite", "realm": s.config.Realm, "password_only": true}, nil
}

// GetName returns the configured portal selection name.
func (s *Store) GetName() string { return s.config.Name }

// GetRealm returns the immutable account realm.
func (s *Store) GetRealm() string { return s.config.Realm }

// GetKind distinguishes this backend from the local JSON database.
func (s *Store) GetKind() string { return "sqlite" }

// GetConfig exposes safe runtime identifiers, excluding file paths and accounts.
func (s *Store) GetConfig() map[string]any {
	return map[string]any{"name": s.config.Name, "realm": s.config.Realm, "kind": "sqlite"}
}

// Configure checks an already-open handle without mutating configuration.
func (s *Store) Configure() error {
	return s.db.Read(context.Background(), func(context.Context, *sql.Tx) error { return nil })
}

// Configured reports whether the current handle is usable.
func (s *Store) Configured() bool { return s != nil && s.Configure() == nil }

// Reload observes fresh state; reopening with New creates a new proof epoch.
func (s *Store) Reload() error { return s.Configure() }

// GetLoginIcon returns a detached password-login icon.
func (s *Store) GetLoginIcon() *icons.LoginIcon {
	icon := icons.NewLoginIcon("local")
	icon.SetRealm(s.config.Realm)
	icon.Text = "SQLite"
	return icon
}

// Close drains connections while retaining account data.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

// AddUser creates an account with a generated password for trusted management.
func (s *Store) AddUser(username, email, name string, roles []string) (map[string]any, error) {
	password := randomPassword()
	data, err := s.Create(context.Background(), &Account{Username: username, Email: email, Name: name, Roles: roles}, password)
	if err != nil {
		return nil, err
	}
	data["password"] = password
	return data, nil
}
func randomPassword() string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// ResetUserPassword returns a generated replacement only after durable mutation.
func (s *Store) ResetUserPassword(username, email string) (map[string]any, error) {
	password := randomPassword()
	if err := s.SetPassword(context.Background(), username, email, password); err != nil {
		return nil, err
	}
	return map[string]any{"username": username, "password": password}, nil
}

// OverwriteUserRoles replaces trusted role assignments and invalidates evidence.
func (s *Store) OverwriteUserRoles(username, email string, roles []string) (map[string]any, error) {
	var out map[string]any
	err := s.mutate(context.Background(), username, email, func(ctx context.Context, tx *sql.Tx, a accountRecord) error {
		a.account.Roles = roles
		normalized, err := normalizeAccount(&a.account)
		if err != nil {
			return err
		}
		data, _ := json.Marshal(normalized.Roles)
		if _, err := tx.ExecContext(ctx, "UPDATE accounts SET roles=?,version=version+1 WHERE id=?", data, a.id); err != nil {
			return err
		}
		out = accountMap(a.id, normalized)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AddUserRoles is unsupported; callers must supply a complete replacement.
func (s *Store) AddUserRoles(string, string, []string) (map[string]any, error) {
	return nil, ErrUnsupported
}

// OverwriteUserAuthChallengeRules rejects unsupported account-specific factors.
func (s *Store) OverwriteUserAuthChallengeRules(string, string, []string) (map[string]any, error) {
	return nil, ErrUnsupported
}

var _ ids.IdentityStore = (*Store)(nil)
