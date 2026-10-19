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

// Package attachment owns external authentication's local identity-store binding.
package attachment

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Config names an explicit local identity store. Omission creates a private
// in-memory database for the lifetime of the provider instance.
type Config struct {
	LocalIdentityStore string `json:"local_identity_store,omitempty" xml:"local_identity_store,omitempty" yaml:"local_identity_store,omitempty"`
}

// Validate rejects ambiguous names without starting a database or provider.
func (c Config) Validate() error {
	s := c.LocalIdentityStore
	if len(s) > 256 || !utf8.ValidString(s) || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\x00\r\n") || s == ":memory:" {
		return fmt.Errorf("invalid attached local identity store name")
	}
	return nil
}

// Store is the transaction capability required from an attached local store.
type Store interface {
	ResolveExternalAccount(context.Context, identity.ExternalAccount, bool) (*identity.ExternalAccountIdentity, error)
	ConnectExternalAccount(context.Context, identity.ExternalAccount, requests.AuthenticationEvidence, requests.AuthenticationEvidence) (*identity.ExternalAccountIdentity, error)
	WithRefreshIdentity(context.Context, requests.AuthenticationEvidence, func(identity.RefreshIdentity) error) error
}

// Consumer exposes a provider-owned binding, shared by its portal/policy consumers.
type Consumer interface{ IdentityAttachment() *Attachment }

// Attachment resolves identities without exposing its database as a login realm.
// An unbound explicit name fails closed; it never falls back to memory.
type Attachment struct {
	mu     sync.Mutex
	config Config
	store  Store
}

// New constructs a binding. The memory database is initialized on first use.
func New(config Config) (*Attachment, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Attachment{config: config}, nil
}

// StoreName returns the explicit local identity store name, or empty for memory.
func (a *Attachment) StoreName() string { return a.config.LocalIdentityStore }

// BindStore installs a concrete store pointer before requests are served. The
// pointer constraint makes nil checks and instance comparison safe without
// reflection, including when the pointed-to store contains maps or slices.
// Rebinding to a different instance cannot replace the attachment's authority.
func BindStore[T any, S interface {
	*T
	Store
}](a *Attachment, store S) error {
	if a == nil || store == nil || a.StoreName() == "" {
		return fmt.Errorf("invalid identity attachment binding")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil && a.store != store {
		return fmt.Errorf("identity attachment is already bound")
	}
	a.store = store
	return nil
}

// Store returns the configured transaction capability, creating only the
// implicit, passwordless memory database. No default administrator is generated.
func (a *Attachment) Store() (Store, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		return a.store, nil
	}
	if a.StoreName() != "" {
		return nil, fmt.Errorf("attached local identity store is not bound")
	}
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		return nil, err
	}
	a.store = db
	return db, nil
}

// Authenticate resolves an already verified upstream subject and captures its
// current local proof. The provider owns issuer/subject extraction and trust.
func (a *Attachment) Authenticate(ctx context.Context, r *requests.Request, provider, kind string) error {
	r.ExternalIdentity.Evidence = requests.AuthenticationEvidence{}
	r.ExternalIdentity.Provider, r.ExternalIdentity.Kind = provider, kind
	account := ExternalAccount(r.ExternalIdentity)
	if claims, ok := r.Response.Payload.(map[string]any); ok {
		account.Email, _ = claims["email"].(string)
		account.Name, _ = claims["name"].(string)
	} else {
		account.Email, account.Name = r.User.Email, r.User.FullName
	}
	store, err := a.Store()
	if err != nil {
		return err
	}
	resolved, err := store.ResolveExternalAccount(ctx, account, true)
	if err != nil {
		return err
	}
	r.ExternalIdentity.Evidence = resolved.Evidence
	return nil
}

// ExternalAccount converts server-held proof into an exact connection key.
func ExternalAccount(proof requests.ExternalIdentity) identity.ExternalAccount {
	return identity.ExternalAccount{Provider: proof.Provider, Kind: proof.Kind, Issuer: proof.Issuer, Subject: proof.Subject}
}
