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

package rsapss

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

// Signer is an immutable key snapshot implementing tokenrefresh.Signer. It is
// safe for concurrent calls, retains no caller claims, and owns no open files or
// workers. Construct a new signer and consumer to rotate; keep old public keys
// available until their tokens expire. This local key is not an HSM boundary.
type Signer struct {
	config Config
	key    *rsa.PrivateKey
	header string
	jwks   []byte
	maxAge int64
}

var _ tokenrefresh.Signer = (*Signer)(nil)

// New validates an independent config and reads one bounded, regular PEM file.
// Reload failures leave previously constructed signers usable. No key generation,
// environment expansion, registration, or private-key export occurs.
func New(config *Config) (*Signer, error) {
	if config == nil {
		return nil, fmt.Errorf("PS256 signing config is required")
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	key, err := readKey(c.KeyFile)
	if err != nil {
		return nil, err
	}
	header, _ := json.Marshal(map[string]string{"alg": c.Algorithm, "kid": c.KeyID, "typ": TokenType})
	public := &key.PublicKey
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "alg": c.Algorithm, "kid": c.KeyID,
		"use": "sig", "n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
	lifetime, _ := time.ParseDuration(c.MaxLifetime)
	return &Signer{config: c, key: key, header: base64.RawURLEncoding.EncodeToString(header), jwks: jwks, maxAge: int64(lifetime / time.Second)}, nil
}

func readKey(filename string) (*rsa.PrivateKey, error) {
	invalid := func() (*rsa.PrivateKey, error) {
		return nil, fmt.Errorf("PS256 signing private key is unavailable or invalid")
	}
	// Reject special files before opening so a configured FIFO cannot block startup.
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return invalid()
	}
	f, err := os.Open(filename)
	if err != nil {
		return invalid()
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 {
		return invalid()
	}
	data, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	defer clear(data)
	if err != nil || len(data) > 16<<10 {
		return invalid()
	}
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) && !bytes.HasPrefix(data, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		return invalid()
	}
	block, rest := pem.Decode(data)
	if block == nil || bytes.Count(data, []byte("-----BEGIN ")) != 1 || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return invalid()
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return invalid()
		}
		key, _ = parsed.(*rsa.PrivateKey)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return invalid()
		}
	default:
		return invalid()
	}
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || len(key.Primes) != 2 || key.Validate() != nil {
		return invalid()
	}
	// Complete precomputation before publishing this immutable snapshot.
	key.Precompute()
	return key, nil
}

// PublicJWKS returns a detached public-only key set for this key version.
// Hosts own the HTTP discovery route and rotation overlap. Nothing here publishes
// a portal or OIDC JWKS route, or exports private material.
func (s *Signer) PublicJWKS() ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, fmt.Errorf("PS256 signer is uninitialized")
	}
	return slices.Clone(s.jwks), nil
}

// Sign signs already approved access claims without adding, dropping or changing
// claims. The caller authenticates and authorizes issuance and must not mutate
// claims during this call. The trusted config controls alg, kid and typ headers.
// Issuer, sole audience, subject and integer iat/nbf/exp claims are required.
// Cancellation or expiry yields no token. A signature alone does not commit a
// session; use the refresh manager's staged issuance/rotation workflow.
func (s *Signer) Sign(ctx context.Context, claims map[string]any) (string, error) {
	if s == nil || s.key == nil || ctx == nil {
		return "", fmt.Errorf("PS256 signer and context are required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	payload, snapshot, err := encodeClaims(claims)
	if err != nil {
		return "", err
	}
	expiry, err := s.validateClaims(snapshot, time.Now().Unix())
	if err != nil {
		return "", err
	}
	input := s.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	// RFC 7518 PS256 requires SHA-256, MGF1-SHA-256 and a 32-byte salt.
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPSS(rand.Reader, s.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("PS256 signing failed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	now := time.Now()
	if deadline, ok := ctx.Deadline(); ok && !now.Before(deadline) {
		return "", context.DeadlineExceeded
	}
	if now.Unix() >= expiry {
		return "", fmt.Errorf("PS256 signing claims expired")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Signer) validateClaims(claims map[string]any, now int64) (int64, error) {
	invalid := func() (int64, error) {
		return 0, fmt.Errorf("PS256 signing claims violate the configured binding or lifetime")
	}
	if claims["iss"] != s.config.Issuer {
		return invalid()
	}
	subject, ok := claims["sub"].(string)
	if !ok || !validText(subject, 1024) {
		return invalid()
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != s.config.Audience {
			return invalid()
		}
	case []any:
		if len(aud) != 1 || aud[0] != s.config.Audience {
			return invalid()
		}
	default:
		return invalid()
	}
	var times [3]int64
	for i, name := range []string{"iat", "nbf", "exp"} {
		value, ok := claims[name].(json.Number)
		if !ok {
			return invalid()
		}
		n, err := value.Int64()
		if err != nil || n <= 0 {
			return invalid()
		}
		times[i] = n
	}
	iat, nbf, exp := times[0], times[1], times[2]
	if iat > now || nbf > now || nbf < iat || exp <= now || exp <= nbf || exp-iat > s.maxAge {
		return invalid()
	}
	return exp, nil
}
