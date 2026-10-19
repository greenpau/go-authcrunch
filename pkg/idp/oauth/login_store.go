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

package oauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
)

// LoginStoreConfig selects a host-injected store. Omission retains private memory.
// Namespace identifies a deployment; the provider adds a configuration digest.
type LoginStoreConfig struct {
	Name      string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Namespace string `json:"namespace,omitempty" xml:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// Validate checks identifiers without accessing storage.
func (c *LoginStoreConfig) Validate() error {
	if c == nil || !loginText(c.Name, 128) || !loginText(c.Namespace, 128) {
		return fmt.Errorf("OAuth login storage requires a name and namespace")
	}
	return nil
}

// LoginBinding identifies the initiating browser and exact callback endpoint.
// Browser is SHA-256 of the protected SessionID supplied by the consumer.
type LoginBinding struct {
	Browser  [32]byte `json:"browser,omitempty" xml:"browser,omitempty" yaml:"browser,omitempty"`
	Callback string   `json:"callback,omitempty" xml:"callback,omitempty" yaml:"callback,omitempty"`
}

// LoginTransaction is private server evidence, never an HTTP input. Stores must
// preserve every field. Deadlines are Unix seconds; offline time counts. Claim
// is empty until atomically assigned by Claim. Records contain private PKCE data.
type LoginTransaction struct {
	State         string       `json:"state,omitempty" xml:"state,omitempty" yaml:"state,omitempty"`
	Nonce         string       `json:"nonce,omitempty" xml:"nonce,omitempty" yaml:"nonce,omitempty"`
	NonceRequired bool         `json:"nonce_required,omitempty" xml:"nonce_required,omitempty" yaml:"nonce_required,omitempty"`
	Verifier      string       `json:"verifier,omitempty" xml:"verifier,omitempty" yaml:"verifier,omitempty"`
	Binding       LoginBinding `json:"binding" xml:"binding" yaml:"binding"`
	ReturnURL     string       `json:"return_url,omitempty" xml:"return_url,omitempty" yaml:"return_url,omitempty"`
	CreatedAt     int64        `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	ExpiresAt     int64        `json:"expires_at,omitempty" xml:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Claim         string       `json:"claim,omitempty" xml:"claim,omitempty" yaml:"claim,omitempty"`
}

var (
	// ErrLoginInvalid indicates a missing, expired, consumed or mismatched login.
	ErrLoginInvalid = errors.New("OAuth login transaction is invalid")
	// ErrLoginCapacity means existing transactions were preserved at capacity.
	ErrLoginCapacity = errors.New("OAuth login storage is at capacity")
	// ErrLoginUnavailable means no credential or successful redirect may be issued.
	ErrLoginUnavailable = errors.New("OAuth login storage is unavailable")
)

// LoginStore supplies linearizable, namespace-isolated OAuth transactions.
// Create never overwrites an existing state. Claim checks expiry, exact binding
// and an empty Claim atomically, installs the supplied unpredictable claim ID,
// and returns the complete record. Wrong bindings do not consume transactions.
// Get returns an independent, unexpired snapshot, including the current claim.
// Complete atomically deletes only an unexpired transaction with that claim.
// Cancel deletes pending or claimed transactions only for the exact binding.
// Missing/mismatched cancellation returns false, nil. Other invalid operations
// return ErrLoginInvalid; capacity returns ErrLoginCapacity. Backend failures
// return errors and MUST NOT publish tentative results. Honor context deadlines.
//
// Acknowledged claims/cancellations must survive supported backend failover;
// never resurrect a claim after an ambiguous commit or a worker crash. Expiry is
// checked inside operations, not just by cleanup. Synchronize replica/backend
// clocks; Validate permits only bounded creation skew, never an expiry grace.
// Protect record confidentiality, integrity and transport. Storage is trusted
// authentication infrastructure, not a generic eventually consistent cache.
// The embedding host owns injected stores and closes them after all consumers
// drain. Provider.Close never closes or purges an injected store.
type LoginStore interface {
	Create(context.Context, string, LoginTransaction) error
	Claim(context.Context, string, string, LoginBinding, string) (LoginTransaction, error)
	Get(context.Context, string, string) (LoginTransaction, error)
	Complete(context.Context, string, string, string) error
	Cancel(context.Context, string, string, LoginBinding) (bool, error)
}

// Validate checks bounded transaction evidence at the current backend time.
// Creation timestamps may be at most 30 seconds ahead to tolerate small replica
// clock differences. Expiry has no grace period. Creation requires an empty Claim
// in addition to these invariants.
func (t LoginTransaction) Validate(now time.Time) error {
	if !loginText(t.State, 128) || t.Binding.Browser == [32]byte{} || !loginText(t.Binding.Callback, 8192) ||
		len(t.ReturnURL) > 32768 || !utf8.ValidString(t.ReturnURL) || strings.ContainsAny(t.ReturnURL, "\x00\r\n") ||
		(t.Nonce != "" && !loginText(t.Nonce, 128)) || (t.Verifier != "" && !loginText(t.Verifier, 128)) || t.NonceRequired != (t.Nonce != "") ||
		t.CreatedAt <= 0 || t.CreatedAt > now.Add(30*time.Second).Unix() || t.ExpiresAt <= now.Unix() ||
		t.ExpiresAt <= t.CreatedAt || t.ExpiresAt-t.CreatedAt > int64(oauthLoginLifetime/time.Second) ||
		(t.Claim != "" && !loginText(t.Claim, 128)) {
		return ErrLoginInvalid
	}
	return nil
}

// Matches compares a browser binding without consuming a transaction.
func (b LoginBinding) Matches(other LoginBinding) bool {
	return b.Browser != [32]byte{} && b.Callback != "" && b.Callback == other.Callback && subtle.ConstantTimeCompare(b.Browser[:], other.Browser[:]) == 1
}

func loginText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

func loginStoreError(err error) error {
	if errors.Is(err, ErrLoginInvalid) {
		return autherrors.ErrIdentityProviderOauthAuthorizationStateNotFound
	}
	return ErrLoginUnavailable
}
