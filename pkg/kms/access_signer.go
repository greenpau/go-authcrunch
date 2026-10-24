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

package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/internal/accessclaims"
)

// AccessTokenType separates portal access grants from other JWT purposes.
const AccessTokenType = "authcrunch-access+jwt"

// AccessSignerPolicy is the immutable authority of a selected access signer.
type AccessSignerPolicy struct {
	Algorithm          string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	KeyID              string `json:"key_id,omitempty" xml:"key_id,omitempty" yaml:"key_id,omitempty"`
	TokenType          string `json:"token_type,omitempty" xml:"token_type,omitempty" yaml:"token_type,omitempty"`
	Issuer             string `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Audience           string `json:"audience,omitempty" xml:"audience,omitempty" yaml:"audience,omitempty"`
	MaxLifetimeSeconds int    `json:"max_lifetime_seconds,omitempty" xml:"max_lifetime_seconds,omitempty" yaml:"max_lifetime_seconds,omitempty"`
}

// ExternalAccessSignerConfig is a serializable declaration, never a live signer.
type ExternalAccessSignerConfig struct {
	Name         string             `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Kind         string             `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	ConfigDigest string             `json:"config_digest,omitempty" xml:"config_digest,omitempty" yaml:"config_digest,omitempty"`
	Policy       AccessSignerPolicy `json:"policy" xml:"policy" yaml:"policy"`
}

// AccessSignerMetadata attests initialized immutable runtime configuration.
type AccessSignerMetadata struct {
	Kind         string             `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	ConfigDigest string             `json:"config_digest,omitempty" xml:"config_digest,omitempty" yaml:"config_digest,omitempty"`
	Policy       AccessSignerPolicy `json:"policy" xml:"policy" yaml:"policy"`
}

// AccessSigner signs approved claims. The caller owns its lifetime. Sign must
// return no token on error; the consumer independently verifies every result.
type AccessSigner interface {
	Sign(context.Context, map[string]any) (string, error)
	PublicJWKS() ([]byte, error)
	Metadata() (AccessSignerMetadata, error)
}

// AccessSignerBinding associates one declared signer with its borrowed runtime.
// Configure before publication; neither a portal nor a root closes the signer.
type AccessSignerBinding struct {
	prepared *preparedAccessSigner
	Config   *ExternalAccessSignerConfig `json:"-" xml:"-" yaml:"-"`
	Signer   AccessSigner                `json:"-" xml:"-" yaml:"-"`
}

// NewExternalAccessSignerConfig hashes a backend's validated normalized config.
func NewExternalAccessSignerConfig(name, kind string, policy AccessSignerPolicy, normalizedConfig any) (*ExternalAccessSignerConfig, error) {
	data, err := json.Marshal(normalizedConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid access signer configuration")
	}
	digest := sha256.Sum256(data)
	cfg := &ExternalAccessSignerConfig{Name: name, Kind: kind, Policy: policy, ConfigDigest: hex.EncodeToString(digest[:])}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks declaration metadata without key or storage access.
func (c *ExternalAccessSignerConfig) Validate() error {
	if c == nil || !accessText(c.Name, 128) || !accessText(c.Kind, 128) || len(c.ConfigDigest) != 64 || strings.ToLower(c.ConfigDigest) != c.ConfigDigest {
		return fmt.Errorf("invalid access signer declaration")
	}
	if _, err := hex.DecodeString(c.ConfigDigest); err != nil {
		return fmt.Errorf("invalid access signer digest")
	}
	if c.Policy.Algorithm != "PS256" || c.Policy.TokenType != AccessTokenType || !accessKeyID(c.Policy.KeyID) {
		return fmt.Errorf("invalid access signer policy")
	}
	profile := &AccessTokenProfileConfig{Issuer: c.Policy.Issuer, Audience: c.Policy.Audience, KeyIDs: []string{c.Policy.KeyID}, MaxLifetimeSeconds: c.Policy.MaxLifetimeSeconds}
	return profile.Validate()
}
func accessText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}
func accessKeyID(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.')
	})
}

// ValidateAccessSignerBinding contains only plugin metadata access. It does not
// acquire, sign with or close a backend; operational panics remain visible.
func ValidateAccessSignerBinding(binding *AccessSignerBinding) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid access signer runtime metadata")
		}
	}()
	if binding == nil || binding.Config.Validate() != nil || binding.Signer == nil {
		return fmt.Errorf("invalid access signer runtime binding")
	}
	metadata, err := binding.Signer.Metadata()
	if err != nil || metadata.Kind != binding.Config.Kind || metadata.ConfigDigest != binding.Config.ConfigDigest || metadata.Policy != binding.Config.Policy {
		return fmt.Errorf("access signer metadata does not match declaration")
	}
	return nil
}

type preparedAccessSigner struct {
	config ExternalAccessSignerConfig
	signer AccessSigner
	jwks   []byte
}

// Prepare captures metadata and public keys once, before consumer publication.
// The returned binding has a private immutable runtime snapshot. Subsequent
// Prepare/Sign calls use that snapshot, never replacements of its exported input
// fields. The signer remains borrowed; callers must not mutate its runtime.
func (b *AccessSignerBinding) Prepare() (*AccessSignerBinding, error) {
	if b == nil {
		return nil, fmt.Errorf("access signer binding is required")
	}
	prepared := b.prepared
	if prepared == nil {
		if err := ValidateAccessSignerBinding(b); err != nil {
			return nil, err
		}
		config := *b.Config
		data, err := readAccessSignerJWKS(b.Signer)
		if err != nil {
			return nil, err
		}
		object, err := accessclaims.Decode(data)
		if err != nil || len(object) != 1 {
			return nil, fmt.Errorf("invalid access signer public keys")
		}
		keys, ok := object["keys"].([]any)
		if !ok || len(keys) != 1 {
			return nil, fmt.Errorf("invalid access signer public keys")
		}
		key, ok := keys[0].(map[string]any)
		if !ok || len(key) != 6 || key["kty"] != "RSA" || key["alg"] != "PS256" || key["use"] != "sig" || key["kid"] != config.Policy.KeyID {
			return nil, fmt.Errorf("invalid access signer public key")
		}
		for _, field := range []string{"n", "e"} {
			value, ok := key[field].(string)
			if !ok {
				return nil, fmt.Errorf("invalid access signer public key")
			}
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
			if err != nil || len(decoded) == 0 || decoded[0] == 0 || base64.RawURLEncoding.EncodeToString(decoded) != value {
				return nil, fmt.Errorf("invalid access signer public key")
			}
			number := new(big.Int).SetBytes(decoded)
			if field == "n" && (number.BitLen() < 2048 || number.BitLen() > 8192 || number.Bit(0) == 0) || field == "e" && (!number.IsInt64() || number.Int64() < 3 || number.Int64() > 1<<31-1 || number.Bit(0) == 0) {
				return nil, fmt.Errorf("invalid access signer RSA public key")
			}
		}
		prepared = &preparedAccessSigner{config: config, signer: b.Signer, jwks: bytes.Clone(data)}
	}
	config := prepared.config
	return &AccessSignerBinding{Config: &config, Signer: prepared.signer, prepared: prepared}, nil
}
func readAccessSignerJWKS(signer AccessSigner) (data []byte, err error) {
	defer func() {
		if recover() != nil {
			data = nil
			err = fmt.Errorf("invalid access signer public metadata")
		}
	}()
	data, err = signer.PublicJWKS()
	if err != nil || len(data) > 64<<10 {
		return nil, fmt.Errorf("invalid access signer public metadata")
	}
	return data, nil
}

// Sign invokes the captured borrowed signer; it does not authorize its output.
// Consumers must verify the returned token against trusted keys and claims.
func (b *AccessSignerBinding) Sign(ctx context.Context, claims map[string]any) (string, error) {
	if b == nil || b.prepared == nil {
		return "", fmt.Errorf("access signer is not prepared")
	}
	return b.prepared.signer.Sign(ctx, claims)
}
