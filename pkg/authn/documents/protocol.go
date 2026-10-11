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

package documents

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Protocol identifies the immutable wire and browser crypto contract.
const Protocol = "authcrunch-documents"

// Domain errors intentionally reveal no database details or account attributes.
var (
	ErrInvalid          = errors.New("invalid documents request")
	ErrNotFound         = errors.New("document resource not found")
	ErrConflict         = errors.New("document resource conflict")
	ErrQuota            = errors.New("documents quota exceeded")
	ErrIdentityConflict = errors.New("documents identity source conflict")
)

// Key is an immutable P-256 key registration. Vault contains the 32-byte private
// scalar encrypted with a separate random 32-byte recovery key. All binary JSON
// fields use canonical unpadded base64url, never Go's default []byte encoding.
type Key struct {
	UserID    string `json:"user_id" xml:"user_id" yaml:"user_id"`
	KeyID     string `json:"key_id" xml:"key_id" yaml:"key_id"`
	PublicKey string `json:"public_key" xml:"public_key" yaml:"public_key"`
	Vault     *Vault `json:"vault,omitempty" xml:"vault,omitempty" yaml:"vault,omitempty"`
}

// Vault holds AES-256-GCM ciphertext and its fresh random nonce and HKDF salt.
type Vault struct {
	Salt       string `json:"salt" xml:"salt" yaml:"salt"`
	Nonce      string `json:"nonce" xml:"nonce" yaml:"nonce"`
	Ciphertext string `json:"ciphertext" xml:"ciphertext" yaml:"ciphertext"`
}

// Envelope wraps a document's 32-byte key for one registered recipient using
// ephemeral P-256 ECDH, HKDF-SHA256 and AES-256-GCM. Context binds both identities,
// the portal, document, recipient key, and ephemeral key.
type Envelope struct {
	KeyID        string `json:"key_id" xml:"key_id" yaml:"key_id"`
	EphemeralKey string `json:"ephemeral_key" xml:"ephemeral_key" yaml:"ephemeral_key"`
	Ciphertext   string `json:"ciphertext" xml:"ciphertext" yaml:"ciphertext"`
}

// Manifest contains encrypted filename/media metadata and the owner's envelope.
// It is immutable once set. Chunks are also immutable; retries must be identical.
type Manifest struct {
	Metadata string   `json:"metadata" xml:"metadata" yaml:"metadata"`
	Envelope Envelope `json:"envelope" xml:"envelope" yaml:"envelope"`
}

// File is a bounded descriptor. Envelope is only the requesting user's envelope;
// listing never returns metadata ciphertext or other recipients' envelopes.
type File struct {
	ID        string    `json:"id" xml:"id" yaml:"id"`
	Owner     string    `json:"owner" xml:"owner" yaml:"owner"`
	Size      int64     `json:"size" xml:"size" yaml:"size"`
	Chunks    int       `json:"chunks" xml:"chunks" yaml:"chunks"`
	State     string    `json:"state" xml:"state" yaml:"state"`
	CreatedAt int64     `json:"created_at" xml:"created_at" yaml:"created_at"`
	ExpiresAt int64     `json:"expires_at,omitempty" xml:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Metadata  string    `json:"metadata,omitempty" xml:"metadata,omitempty" yaml:"metadata,omitempty"`
	Envelope  *Envelope `json:"envelope,omitempty" xml:"envelope,omitempty" yaml:"envelope,omitempty"`
}

// Page uses an opaque document ID as its exclusive cursor. It is not a snapshot
// across requests; concurrent insertions may be visible on a later listing.
type Page struct {
	Files []File `json:"files" xml:"files" yaml:"files"`
	Next  string `json:"next,omitempty" xml:"next,omitempty" yaml:"next,omitempty"`
}

func decode(value string, min, max int) ([]byte, error) {
	if len(value) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) < min || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, ErrInvalid
	}
	return b, nil
}

// ValidID checks a canonical 256-bit identifier or key fingerprint.
func ValidID(value string) bool { _, err := decode(value, 32, 32); return err == nil }

func randomID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidUserID accepts the canonical lowercase UUID stored in identity.User.ID.
// It is distinct from random document/portal IDs and key fingerprints.
func ValidUserID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return value != "00000000-0000-0000-0000-000000000000"
}

func publicKey(value string) ([]byte, error) {
	b, err := decode(value, 65, 65)
	if err != nil {
		return nil, err
	}
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

func (k Key) validate(userID string) error {
	if !ValidUserID(userID) || k.UserID != userID || k.Vault == nil {
		return ErrInvalid
	}
	b, err := publicKey(k.PublicKey)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if k.KeyID != base64.RawURLEncoding.EncodeToString(h[:]) {
		return ErrInvalid
	}
	for _, field := range []struct {
		value string
		size  int
	}{{k.Vault.Salt, 32}, {k.Vault.Nonce, 12}, {k.Vault.Ciphertext, 48}} {
		if _, err := decode(field.value, field.size, field.size); err != nil {
			return err
		}
	}
	return nil
}

func (e Envelope) validate() error {
	if !ValidID(e.KeyID) {
		return ErrInvalid
	}
	if _, err := publicKey(e.EphemeralKey); err != nil {
		return err
	}
	_, err := decode(e.Ciphertext, 48, 48)
	return err
}
