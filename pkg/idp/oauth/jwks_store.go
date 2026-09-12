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

package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	maxOAuthJwksBytes        = 1 << 20
	maxOAuthJwksKeys         = 64
	maxOAuthKeyFetchAttempts = 4
	oauthKeyFetchCooldown    = 5 * time.Minute
)

// An immutable snapshot retains same-kid alternatives and keys without an ID.
type oauthJwksSet struct {
	all  []*JwksKey
	byID map[string][]*JwksKey
}

func newOAuthJwksSet(keys []*JwksKey) oauthJwksSet {
	s := oauthJwksSet{all: keys, byID: make(map[string][]*JwksKey)}
	for _, key := range keys {
		s.byID[key.KeyID] = append(s.byID[key.KeyID], key)
	}
	return s
}

func (b *IdentityProvider) snapshotKeys() (oauthJwksSet, uint64) {
	b.keyMu.RLock()
	defer b.keyMu.RUnlock()
	return b.keys, b.keyFetchVersion
}

func (b *IdentityProvider) installStaticKeys() error {
	if len(b.config.JwksKeys) > maxOAuthJwksKeys {
		return fmt.Errorf("OAuth static key set exceeds %d keys", maxOAuthJwksKeys)
	}
	ids := make([]string, 0, len(b.config.JwksKeys))
	for id := range b.config.JwksKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keys := make([]*JwksKey, 0, len(ids))
	for _, id := range ids {
		key, err := NewJwksKeyFromPublicKeyPEM(id, b.config.JwksKeys[id])
		if err != nil {
			return errors.ErrIdentityProviderConfig.WithArgs(fmt.Errorf("failed loading kid %q: %w", id, err))
		}
		keys = append(keys, key)
	}
	b.staticKeys = newOAuthJwksSet(keys)
	b.keyMu.Lock()
	b.keys = b.staticKeys
	b.keyMu.Unlock()
	return nil
}

func (b *IdentityProvider) canFetchKeys() bool {
	return !b.disableKeyVerification && b.keysURL != ""
}

func (b *IdentityProvider) fetchKeysURL() error { return b.refreshKeys(context.Background(), nil) }

// A request retries at most once against a fresh snapshot. A version includes
// failed fetches so waiters share both success and failure, not another request.
func (b *IdentityProvider) refreshKeys(ctx context.Context, version *uint64) error {
	b.keyFetchMu.Lock()
	defer b.keyFetchMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	_, current := b.snapshotKeys()
	if version != nil && *version != current {
		return b.keyFetchError
	}
	if b.keyFetchAttempts >= maxOAuthKeyFetchAttempts {
		if time.Since(b.lastKeyFetch) < oauthKeyFetchCooldown {
			return errors.ErrIdentityProviderOauthJwksKeysTooManyAttempts
		}
		b.keyFetchAttempts = 0
	}
	b.lastKeyFetch = time.Now()
	b.keyFetchAttempts++
	remote, authoritative, err := b.fetchRemoteKeys(ctx)
	b.keyMu.Lock()
	if authoritative {
		// Explicit static IDs take precedence; a remote set cannot replace pins.
		keys := append([]*JwksKey(nil), b.staticKeys.all...)
		for _, key := range remote {
			if _, pinned := b.staticKeys.byID[key.KeyID]; !pinned {
				keys = append(keys, key)
			}
		}
		b.keys = newOAuthJwksSet(keys)
	}
	b.keyFetchVersion++
	b.keyMu.Unlock()
	b.keyFetchError = err
	return err
}

// authoritative distinguishes an empty/unsupported replacement from a failed
// transport or malformed document. Only a complete keys array replaces trust.
func (b *IdentityProvider) fetchRemoteKeys(ctx context.Context) ([]*JwksKey, bool, error) {
	client, err := b.newBrowser()
	if err != nil {
		return nil, false, err
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.keysURL, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("OAuth JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthJwksBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxOAuthJwksBytes {
		return nil, false, fmt.Errorf("OAuth JWKS response exceeds %d bytes", maxOAuthJwksBytes)
	}
	return parseOAuthJwks(body)
}

func parseOAuthJwks(body []byte) ([]*JwksKey, bool, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, false, err
	}
	raw, exists := document["keys"]
	if !exists {
		return nil, false, errors.ErrIdentityProviderOauthJwksResponseKeysNotFound
	}
	if raw = bytes.TrimSpace(raw); len(raw) == 0 || raw[0] != '[' {
		return nil, false, fmt.Errorf("OAuth JWKS keys must be an array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, false, err
	}
	if len(entries) > maxOAuthJwksKeys {
		return nil, false, fmt.Errorf("OAuth JWKS exceeds %d keys", maxOAuthJwksKeys)
	}
	keys := make([]*JwksKey, 0, len(entries))
	var keyErrors []error
	for _, entry := range entries {
		key, err := decodeOAuthJwk(entry)
		if err != nil {
			keyErrors = append(keyErrors, err)
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		return keys, true, nil
	}
	if len(keyErrors) > 0 {
		return nil, true, errors.ErrIdentityProviderOauthJwksInvalidKey.WithArgs(keyErrors)
	}
	return nil, true, errors.ErrIdentityProviderOauthJwksKeysNotFound
}

func decodeOAuthJwk(raw json.RawMessage) (*JwksKey, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("OAuth JWK must be an object")
	}
	var key JwksKey
	// Legacy RSA/EC parsers ignored key_ops altogether. Decode it separately
	// so the new OKP restrictions do not change those keys' metadata policy.
	entry := struct {
		*JwksKey
		Operations json.RawMessage `json:"key_ops"`
	}{JwksKey: &key}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, fmt.Errorf("OAuth JWK contains invalid field types")
	}
	if _, present := fields["kid"]; present && key.KeyID == "" {
		return nil, errors.ErrJwksKeyIDEmpty
	}
	if key.KeyType == "OKP" {
		if len(entry.Operations) > 0 {
			if bytes.Equal(bytes.TrimSpace(entry.Operations), []byte("null")) || json.Unmarshal(entry.Operations, &key.KeyOperations) != nil {
				return nil, errors.ErrJwksKeyVerificationOperation.WithArgs(key.KeyID)
			}
		}
		for _, field := range []string{"d", "y", "n", "e", "k"} {
			if _, present := fields[field]; present {
				return nil, errors.ErrJwksKeyPublicParameters.WithArgs(key.KeyID)
			}
		}
		for _, field := range []string{"alg", "use", "key_ops"} {
			if value, present := fields[field]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, fmt.Errorf("OAuth JWK %q has null %s", key.KeyID, field)
			}
		}
		if _, present := fields["alg"]; present && key.Algorithm == "" {
			return nil, errors.ErrJwksKeyAlgoUnsupported.WithArgs(key.Algorithm, key.KeyID)
		}
		if _, present := fields["use"]; present && key.PublicKeyUse == "" {
			return nil, errors.ErrJwksKeyUsageUnsupported.WithArgs(key.PublicKeyUse, key.KeyID)
		}
	}
	if err := key.validatePublicKey(); err != nil {
		return nil, err
	}
	return &key, nil
}

func (s oauthJwksSet) verificationKeys(method, id string, hasID bool) jwtlib.VerificationKeySet {
	candidates := s.all
	if hasID {
		candidates = s.byID[id]
	}
	result := jwtlib.VerificationKeySet{}
	seenEd := make(map[string]bool)
	for _, key := range candidates {
		switch method {
		case "EdDSA", "Ed25519":
			if key.KeyType != "OKP" || (key.Algorithm != "" && key.Algorithm != method) {
				continue
			}
			public, ok := key.publicKey.(ed25519.PublicKey)
			if !ok || len(public) != ed25519.PublicKeySize || seenEd[string(public)] {
				continue
			}
			seenEd[string(public)] = true
			result.Keys = append(result.Keys, public)
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			if public, ok := key.publicKey.(*rsa.PublicKey); ok {
				result.Keys = append(result.Keys, public)
			}
		case "ES256", "ES384", "ES512":
			if public, ok := key.publicKey.(*ecdsa.PublicKey); ok {
				result.Keys = append(result.Keys, public)
			}
		}
	}
	return result
}
