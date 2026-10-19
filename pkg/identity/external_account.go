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

package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// ErrExternalAccountDenied indicates a missing, disabled, moved or revoked account.
var ErrExternalAccountDenied = errors.New("external account denied")

// ExternalAccount is a provider-scoped login identity. Email and display name
// are informational; they never participate in account lookup or connection.
type ExternalAccount struct {
	Provider    string    `json:"provider" xml:"provider" yaml:"provider"`
	Kind        string    `json:"kind" xml:"kind" yaml:"kind"`
	Issuer      string    `json:"issuer" xml:"issuer" yaml:"issuer"`
	Subject     string    `json:"subject" xml:"subject" yaml:"subject"`
	Email       string    `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Name        string    `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	ConnectedAt time.Time `json:"connected_at,omitzero" xml:"connected_at,omitempty" yaml:"connected_at,omitempty"`
}

type externalAccountKey struct{ provider, kind, issuer, subject string }

func (a ExternalAccount) key() externalAccountKey {
	return externalAccountKey{a.Provider, a.Kind, a.Issuer, a.Subject}
}

// Validate checks the exact opaque identity components without normalizing them.
func (a ExternalAccount) Validate() error {
	for _, v := range []string{a.Provider, a.Kind, a.Issuer, a.Subject} {
		if v == "" || len(v) > 4096 || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") || strings.TrimSpace(v) != v {
			return fmt.Errorf("invalid external account identity")
		}
	}
	if len(a.Email) > 1024 || len(a.Name) > 4096 {
		return fmt.Errorf("external account display attributes too large")
	}
	return nil
}

// ExternalAccountIdentity is a detached local record and its current proof.
// Proof is server-only authentication state and is never a wire credential.
type ExternalAccountIdentity struct {
	Account     ExternalAccount                 `json:"-" xml:"-" yaml:"-"`
	Evidence    requests.AuthenticationEvidence `json:"-" xml:"-" yaml:"-"`
	Identity    RefreshIdentity                 `json:"-" xml:"-" yaml:"-"`
	Provisioned bool                            `json:"-" xml:"-" yaml:"-"`
}

// ResolveExternalAccount finds a connection by its complete provider identity.
// Creation makes a passwordless local record with a random, unique ID and name.
// Provider emails are not enrolled as local password-login or recovery aliases.
// Existing connections return their stored metadata, including ConnectedAt;
// display attributes supplied to a lookup do not update the connection.
// Callers must verify the external credential before invoking this trusted API.
func (db *Database) ResolveExternalAccount(ctx context.Context, account ExternalAccount, create bool) (*ExternalAccountIdentity, error) {
	if err := account.Validate(); err != nil {
		return nil, err
	}
	var result *ExternalAccountIdentity
	err := db.externalAccountTransaction(ctx, func(target *Database) (bool, error) {
		u := target.refExternalAccount[account.key()]
		changed := false
		if u == nil {
			if !create {
				return false, ErrExternalAccountDenied
			}
			for {
				u = NewUser("external" + strings.ReplaceAll(NewID(), "-", ""))
				if target.refID[u.ID] == nil && target.refUsername[u.Username] == nil {
					break
				}
			}
			account.ConnectedAt = time.Now().UTC()
			u.ExternallyProvisioned = true
			u.ExternalAccounts = []ExternalAccount{account}
			target.Users = append(target.Users, u)
			if err := target.indexMfaMutationSnapshot(); err != nil {
				return false, err
			}
			changed = true
		}
		if u.Disabled || u.Lockout != nil && u.Lockout.IsLocked() {
			return false, ErrExternalAccountDenied
		}
		var err error
		result, err = target.externalAccountIdentity(u, account)
		return changed, err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ConnectExternalAccount moves a proven external login to a separately proven
// local account. It never merges profile data, roles, passwords or documents.
// An established account cannot be consumed as an automatically created shell.
// Both proofs must be fresh completed logins, rechecked inside one transaction.
func (db *Database) ConnectExternalAccount(ctx context.Context, account ExternalAccount, source, destination requests.AuthenticationEvidence) (*ExternalAccountIdentity, error) {
	if err := account.Validate(); err != nil {
		return nil, err
	}
	if source.Method != "federated" || source.APIKeyID != "" || destination.APIKeyID != "" || destination.Method == "api_key" || destination.Method == "federated" {
		return nil, ErrExternalAccountDenied
	}
	var result *ExternalAccountIdentity
	err := db.externalAccountTransaction(ctx, func(target *Database) (bool, error) {
		from, to := target.refID[source.UserID], target.refID[destination.UserID]
		now := time.Now().Unix()
		for _, proof := range []requests.AuthenticationEvidence{source, destination} {
			u := target.refID[proof.UserID]
			if !target.authenticationEvidenceMatches(proof, u) || proof.AuthenticatedAt <= 0 || proof.AuthenticatedAt > now || now-proof.AuthenticatedAt > 300 || u.Lockout != nil && u.Lockout.IsLocked() {
				return false, ErrExternalAccountDenied
			}
		}
		if target.refExternalAccount[account.key()] != from {
			return false, ErrExternalAccountDenied
		}
		if from == to {
			return false, ErrExternalAccountDenied
		}
		// A disposable shell contains only this login. Refuse implicit account
		// merging once local credentials, factors or other logins exist.
		if !from.ExternallyProvisioned || len(from.ExternalAccounts) != 1 || len(from.Passwords) != 0 || len(from.MfaTokens) != 0 || len(from.APIKeys) != 0 || len(from.PublicKeys) != 0 {
			return false, ErrExternalAccountDenied
		}
		// Use the verified profile stored with the connection, never metadata
		// supplied by the browser or a caller holding only the identity key.
		account = from.ExternalAccounts[0]
		account.ConnectedAt = time.Now().UTC()
		to.ExternalAccounts = append(to.ExternalAccounts, account)
		to.CredentialVersion++
		to.Revise()
		from.ExternalAccounts = nil
		from.Disabled = true
		from.CredentialVersion++
		from.Revise()
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return false, err
		}
		var err error
		result, err = target.externalAccountIdentity(to, account)
		return true, err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (db *Database) externalAccountIdentity(u *User, account ExternalAccount) (*ExternalAccountIdentity, error) {
	index := slices.IndexFunc(u.ExternalAccounts, func(stored ExternalAccount) bool { return stored.key() == account.key() })
	if index < 0 {
		return nil, ErrExternalAccountDenied
	}
	account = u.ExternalAccounts[index]
	challenges, err := u.GetChallenges()
	if err != nil {
		return nil, err
	}
	proof := db.authenticationEvidence(u)
	proof.AuthenticatedAt, proof.Method = time.Now().Unix(), "federated"
	return &ExternalAccountIdentity{Account: account, Evidence: proof, Provisioned: u.ExternallyProvisioned,
		Identity: RefreshIdentity{ExternalAccounts: append([]ExternalAccount(nil), u.ExternalAccounts...), ExternallyProvisioned: u.ExternallyProvisioned, Username: u.Username, Email: u.GetMailClaim(), Name: u.GetNameClaim(), Roles: u.GetRolesClaim(), Challenges: challenges, AuthMethods: u.GetRegisteredAuthMethods(), AuthChallengePolicy: u.HasAuthChallengeRules()}}, nil
}

func (db *Database) indexExternalAccounts() error {
	db.refExternalAccount = make(map[externalAccountKey]*User)
	for _, u := range db.Users {
		for _, account := range u.ExternalAccounts {
			if err := account.Validate(); err != nil {
				return err
			}
			if db.refExternalAccount[account.key()] != nil {
				return fmt.Errorf("duplicate external account connection")
			}
			db.refExternalAccount[account.key()] = u
		}
	}
	return nil
}

// Isolated current snapshots and the canonical file lock make admission and
// connection atomic across goroutines, database instances and process aliases.
func (db *Database) externalAccountTransaction(ctx context.Context, apply func(*Database) (bool, error)) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	run := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var data []byte
		if !db.inMemory {
			var err error
			data, err = os.ReadFile(db.path)
			if err != nil {
				return fmt.Errorf("read external account database: %w", err)
			}
		}
		target, err := db.newIdentityRequestTarget(data)
		if err != nil {
			return err
		}
		if target.Revision != db.Revision {
			// Match WithRefreshIdentity: observing a different file generation
			// invalidates old evidence, including after restoring an old file.
			db.LoadedAt = time.Now().UTC()
			target.LoadedAt = db.LoadedAt
		}
		changed, err := apply(target)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if changed {
			target.inMemory = db.inMemory
			if err := target.commitUnlocked(); err != nil {
				return err
			}
		} else if err := target.persistEpoch(); err != nil {
			return err
		}
		db.adoptMfaMutationSnapshot(target)
		return nil
	}
	if db.inMemory {
		return run()
	}
	return withDatabaseFileLock(db.path, run)
}
