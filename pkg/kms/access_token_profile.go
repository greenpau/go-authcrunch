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
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/internal/accessclaims"
)

// AccessTokenProfileConfig defines an entire consumer's strict PS256 trust
// boundary. It never falls through to unprofiled keys or another JWT purpose.
type AccessTokenProfileConfig struct {
	Issuer             string   `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Audience           string   `json:"audience,omitempty" xml:"audience,omitempty" yaml:"audience,omitempty"`
	KeyIDs             []string `json:"key_ids,omitempty" xml:"key_ids,omitempty" yaml:"key_ids,omitempty"`
	MaxLifetimeSeconds int      `json:"max_lifetime_seconds,omitempty" xml:"max_lifetime_seconds,omitempty" yaml:"max_lifetime_seconds,omitempty"`
}

// Validate normalizes a detached key ID list without reading keys.
func (c *AccessTokenProfileConfig) Validate() error {
	if c == nil || !canonicalAccessIssuer(c.Issuer) || !accessText(c.Audience, 1024) || len(c.KeyIDs) < 1 || len(c.KeyIDs) > 16 || c.MaxLifetimeSeconds < 1 || c.MaxLifetimeSeconds > 86400 {
		return fmt.Errorf("invalid access token profile")
	}
	ids := slices.Clone(c.KeyIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if !accessKeyID(id) || i > 0 && ids[i-1] == id {
			return fmt.Errorf("invalid access token profile key IDs")
		}
	}
	c.KeyIDs = ids
	return nil
}

// Canonical issuer values are exact HTTPS trust identifiers, not rewrite rules.
// Paths may contain endpoint words; an issuer is not a portal mount declaration.
func canonicalAccessIssuer(value string) bool {
	if !accessText(value, 2048) || strings.ContainsAny(value, "%?#\\") || strings.ContainsFunc(value, func(r rune) bool { return r < '!' || r > '~' }) {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || u.String() != value {
		return false
	}
	if u.Path != "" && (u.Path == "/" || path.Clean(u.Path) != u.Path || u.EscapedPath() != u.Path || strings.HasSuffix(u.Path, "/")) {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}
	return true
}

// Clone returns a detached profile configuration.
func (c *AccessTokenProfileConfig) Clone() *AccessTokenProfileConfig {
	if c == nil {
		return nil
	}
	copy := *c
	copy.KeyIDs = slices.Clone(c.KeyIDs)
	return &copy
}

func (ks *CryptoKeyStore) configureAccessTokenProfile() error {
	profile := ks.config.AccessTokenProfile.Clone()
	if profile == nil {
		return nil
	}
	if err := profile.Validate(); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(profile.KeyIDs))
	for _, id := range profile.KeyIDs {
		for _, key := range ks.keys {
			if key.Config == nil || key.Config.Usage == "system" || key.Config.ID != id {
				continue
			}
			if _, exists := keys[id]; exists {
				return fmt.Errorf("duplicate access profile verification key")
			}
			if key.Verify == nil || !key.Verify.Capable {
				return fmt.Errorf("access profile key cannot verify")
			}
			public, ok := key.Verify.Secret.(*rsa.PublicKey)
			if !ok || public == nil || public.N == nil || public.N.BitLen() < 2048 || public.N.BitLen() > 8192 || public.N.Bit(0) == 0 || public.E < 3 || public.E > 1<<31-1 || public.E%2 == 0 {
				return fmt.Errorf("access profile requires RSA verification keys")
			}
			keys[id] = &rsa.PublicKey{N: new(big.Int).Set(public.N), E: public.E}
		}
		if keys[id] == nil {
			return fmt.Errorf("access profile verification key is missing")
		}
	}
	ks.accessProfile = profile
	ks.accessKeys = keys
	return nil
}

// HasAccessTokenProfile reports whether strict access verification is selected.
func (ks *CryptoKeyStore) HasAccessTokenProfile() bool { return ks != nil && ks.accessProfile != nil }

// VerifyAccessToken returns a detached exact-number claim document only after
// strict bounded JOSE, signature and zero-leeway policy validation.
func (ks *CryptoKeyStore) VerifyAccessToken(ctx context.Context, raw string) (map[string]any, error) {
	invalid := func() (map[string]any, error) { return nil, fmt.Errorf("invalid access token") }
	if ks == nil || ks.accessProfile == nil || ctx == nil || ctx.Err() != nil || len(raw) > 96<<10 {
		return invalid()
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return invalid()
	}
	decode := func(value string) ([]byte, error) {
		data, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || base64.RawURLEncoding.EncodeToString(data) != value {
			return nil, fmt.Errorf("invalid access encoding")
		}
		return data, nil
	}
	headerBytes, err := decode(parts[0])
	if err != nil || len(headerBytes) > 1024 {
		return invalid()
	}
	header, err := accessclaims.Decode(headerBytes)
	if err != nil || len(header) != 3 || header["alg"] != "PS256" || header["typ"] != AccessTokenType {
		return invalid()
	}
	kid, ok := header["kid"].(string)
	if !ok || ks.accessKeys[kid] == nil {
		return invalid()
	}
	payload, err := decode(parts[1])
	if err != nil {
		return invalid()
	}
	claims, err := accessclaims.Decode(payload)
	if err != nil {
		return invalid()
	}
	signature, err := decode(parts[2])
	if err != nil {
		return invalid()
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPSS(ks.accessKeys[kid], crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return invalid()
	}
	if err := ks.accessProfile.ValidateClaims(claims, time.Now().Unix()); err != nil || ctx.Err() != nil {
		return invalid()
	}
	return claims, nil
}

// ValidateClaims checks the profile on already approved JSON claims. It does not
// verify a signature and therefore cannot establish authentication by itself.
func (c *AccessTokenProfileConfig) ValidateClaims(claims map[string]any, now int64) error {
	fail := func() error { return fmt.Errorf("invalid access claims") }
	if c == nil || claims["iss"] != c.Issuer {
		return fail()
	}
	subject, ok := claims["sub"].(string)
	if !ok || !accessText(subject, 1024) || !c.AllowsAudience(claims["aud"]) {
		return fail()
	}
	iat, e1 := accessclaims.Integer(claims["iat"])
	nbf, e2 := accessclaims.Integer(claims["nbf"])
	exp, e3 := accessclaims.Integer(claims["exp"])
	if e1 != nil || e2 != nil || e3 != nil || iat <= 0 || nbf < iat || nbf > now || exp <= now || exp-iat > int64(c.MaxLifetimeSeconds) {
		return fail()
	}
	return nil
}

// AllowsAudience accepts exactly the explicitly approved singleton grant.
func (c *AccessTokenProfileConfig) AllowsAudience(value any) bool {
	if c == nil {
		return false
	}
	switch value := value.(type) {
	case string:
		return value == c.Audience
	case []string:
		return len(value) == 1 && value[0] == c.Audience
	case []any:
		return len(value) == 1 && value[0] == c.Audience
	}
	return false
}
func accessPublicJWK(id string, key *rsa.PublicKey) publicJSONWebKey {
	return publicJSONWebKey{KeyType: "RSA", Use: "sig", Algorithm: "PS256", KeyID: id, N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

// AccessTokenTrust identifies already-loaded public trust, without reopening
// files. Empty means legacy verification and preserves legacy persistence hashes.
func (ks *CryptoKeyStore) AccessTokenTrust() string {
	if !ks.HasAccessTokenProfile() {
		return ""
	}
	var keys []publicJSONWebKey
	for _, id := range ks.accessProfile.KeyIDs {
		keys = append(keys, accessPublicJWK(id, ks.accessKeys[id]))
	}
	data, _ := json.Marshal(keys)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// AccessTokenJWKS returns current and explicitly retained profile keys.
func (ks *CryptoKeyStore) AccessTokenJWKS() ([]byte, error) {
	if !ks.HasAccessTokenProfile() {
		return nil, fmt.Errorf("access profile is unavailable")
	}
	var keys []publicJSONWebKey
	for _, id := range ks.accessProfile.KeyIDs {
		keys = append(keys, accessPublicJWK(id, ks.accessKeys[id]))
	}
	return json.Marshal(struct {
		Keys []publicJSONWebKey `json:"keys"`
	}{keys})
}

// MatchAccessSigner validates public discovery and immutable issuing authority
// against this already-loaded verifier. No private key enters its key slots.
func (ks *CryptoKeyStore) MatchAccessSigner(binding *AccessSignerBinding) (err error) {
	if binding == nil || binding.prepared == nil {
		return fmt.Errorf("access signer is not prepared")
	}
	profile := ks.accessProfile
	policy := binding.prepared.config.Policy
	if profile == nil || profile.Issuer != policy.Issuer || profile.Audience != policy.Audience || profile.MaxLifetimeSeconds != policy.MaxLifetimeSeconds || ks.accessKeys[policy.KeyID] == nil {
		return fmt.Errorf("access signer does not match profile")
	}
	for _, key := range ks.signKeys {
		if key.Config.Usage != "system" {
			return fmt.Errorf("selected access signer forbids ordinary signing keys")
		}
	}
	data := binding.prepared.jwks
	object, err := accessclaims.Decode(data)
	if err != nil || len(object) != 1 {
		return fmt.Errorf("invalid access signer public keys")
	}
	keys, ok := object["keys"].([]any)
	if !ok || len(keys) != 1 {
		return fmt.Errorf("invalid access signer public keys")
	}
	key, ok := keys[0].(map[string]any)
	if !ok || len(key) != 6 {
		return fmt.Errorf("invalid access signer public key")
	}
	expected := accessPublicJWK(policy.KeyID, ks.accessKeys[policy.KeyID])
	if key["kty"] != expected.KeyType || key["use"] != expected.Use || key["alg"] != expected.Algorithm || key["kid"] != expected.KeyID || key["n"] != expected.N || key["e"] != expected.E {
		return fmt.Errorf("access signer public key does not match verifier")
	}
	return nil
}
