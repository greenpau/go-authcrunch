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

package oidc

import (
	"crypto"
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

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type oidcSigningKey struct {
	key *rsa.PrivateKey
	id  string
}

func loadSigningKeys(files []string, excluded []crypto.PublicKey) ([]oidcSigningKey, error) {
	var keys []oidcSigningKey
	seen := make(map[string]bool)
	for _, filename := range files {
		f, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("cannot open oidc signing key: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 65537))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > 65536 {
			return nil, fmt.Errorf("cannot read oidc signing key")
		}
		block, rest := pem.Decode(data)
		if block == nil || len(rest) != 0 {
			return nil, fmt.Errorf("oidc signing key must contain exactly one private PEM block")
		}
		var key *rsa.PrivateKey
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			var parsed any
			parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			key, _ = parsed.(*rsa.PrivateKey)
		default:
			return nil, fmt.Errorf("unsupported oidc signing key PEM type")
		}
		if err != nil || key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
			return nil, fmt.Errorf("oidc requires valid 2048 to 8192 bit RSA private keys")
		}
		// Dedicated keys keep ID tokens separate from the host's other JWTs.
		for _, public := range excluded {
			if rsaKey, ok := public.(*rsa.PublicKey); ok {
				if rsaKey == nil || rsaKey.N == nil {
					return nil, fmt.Errorf("invalid excluded RSA public key")
				}
				if key.N.Cmp(rsaKey.N) == 0 && key.E == rsaKey.E {
					return nil, fmt.Errorf("oidc signing keys must be separate from excluded verification keys")
				}
			}
		}
		jwk := oidcPublicKey(&key.PublicKey)
		canonical, _ := json.Marshal(map[string]string{"e": jwk["e"], "kty": "RSA", "n": jwk["n"]})
		digest := sha256.Sum256(canonical)
		id := base64.RawURLEncoding.EncodeToString(digest[:])
		if seen[id] {
			return nil, fmt.Errorf("duplicate oidc signing key material")
		}
		seen[id] = true
		keys = append(keys, oidcSigningKey{key: key, id: id})
	}
	return keys, nil
}

func oidcPublicKey(key *rsa.PublicKey) map[string]string {
	return map[string]string{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

// JWKS returns fresh public key metadata for ID-token verification.
func (o *Provider) JWKS() map[string]any {
	keys := make([]map[string]string, 0, len(o.keys))
	for _, key := range o.keys {
		public := oidcPublicKey(&key.key.PublicKey)
		public["kid"], public["use"], public["alg"] = key.id, "sig", "RS256"
		keys = append(keys, public)
	}
	return map[string]any{"keys": keys}
}

func (o *Provider) sign(claims map[string]any) (string, error) {
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims(claims))
	token.Header["kid"] = o.keys[0].id
	return token.SignedString(o.keys[0].key)
}

func (o *Provider) hintSubject(raw, clientID string) (string, error) {
	// Core permits expired ID token hints. Signature, issuer, audience and
	// subject remain mandatory, so the hint cannot supply login evidence.
	token, err := jwtlib.Parse(raw, func(token *jwtlib.Token) (any, error) {
		id, _ := token.Header["kid"].(string)
		for _, key := range o.keys {
			if key.id == id {
				return &key.key.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("unknown oidc hint key")
	}, jwtlib.WithValidMethods([]string{"RS256"}), jwtlib.WithoutClaimsValidation())
	if err != nil {
		return "", fmt.Errorf("invalid oidc id_token_hint")
	}
	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid oidc id_token_hint claims")
	}
	issuer, _ := claims.GetIssuer()
	audience, _ := claims.GetAudience()
	subject, _ := claims.GetSubject()
	if issuer != o.config.Issuer || len(audience) != 1 || audience[0] != clientID || subject == "" {
		return "", fmt.Errorf("invalid oidc id_token_hint binding")
	}
	return subject, nil
}
