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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// RequestObjectKey is a client's registered public RSA JWK. These keys verify
// Request Objects only; they cannot sign provider tokens. Private and remote
// key material is never accepted through an authorization request.
type RequestObjectKey struct {
	KeyID    string `json:"kid,omitempty" xml:"kid,omitempty" yaml:"kid,omitempty"`
	Modulus  string `json:"n,omitempty" xml:"n,omitempty" yaml:"n,omitempty"`
	Exponent string `json:"e,omitempty" xml:"e,omitempty" yaml:"e,omitempty"`
}

func (k RequestObjectKey) publicKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.Strict().DecodeString(k.Modulus)
	if err != nil || len(n) < 256 || len(n) > 1024 || n[0] == 0 || strings.ContainsAny(k.Modulus, "\r\n") {
		return nil, fmt.Errorf("invalid oidc request object RSA modulus")
	}
	e, err := base64.RawURLEncoding.Strict().DecodeString(k.Exponent)
	if err != nil || len(e) == 0 || len(e) > 4 || e[0] == 0 || strings.ContainsAny(k.Exponent, "\r\n") {
		return nil, fmt.Errorf("invalid oidc request object RSA exponent")
	}
	exponent := new(big.Int).SetBytes(e).Int64()
	modulus := new(big.Int).SetBytes(n)
	if exponent < 3 || exponent > 2147483647 || exponent%2 == 0 || modulus.BitLen() < 2048 || modulus.Bit(0) != 1 {
		return nil, fmt.Errorf("invalid oidc request object RSA key")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent)}, nil
}
func (c *ClientConfig) validateRequestObjectKeys() error {
	if c.RequestObjectSigningAlg != "" && c.RequestObjectSigningAlg != "none" && c.RequestObjectSigningAlg != "RS256" {
		return fmt.Errorf("unsupported oidc request object signing algorithm")
	}
	if (c.RequestObjectSigningAlg == "RS256" && len(c.RequestObjectKeys) == 0) || len(c.RequestObjectKeys) > 8 {
		return fmt.Errorf("invalid oidc request object key count")
	}
	seen := map[string]bool{}
	for _, key := range c.RequestObjectKeys {
		if key.KeyID == "" || len(key.KeyID) > 256 || strings.ContainsAny(key.KeyID, "\r\n\t") || seen[key.KeyID] {
			return fmt.Errorf("invalid oidc request object key ID")
		}
		seen[key.KeyID] = true
		if _, err := key.publicKey(); err != nil {
			return err
		}
	}
	return nil
}
func (o *Provider) verifyRequestObject(clientID string, parts []string, header map[string]json.RawMessage) bool {
	client := o.clients[clientID]
	if client == nil {
		return false
	}
	var alg, kid string
	if json.Unmarshal(header["alg"], &alg) != nil {
		return false
	}
	if raw, ok := header["kid"]; ok {
		if json.Unmarshal(raw, &kid) != nil || kid == "" {
			return false
		}
	}
	if client.RequestObjectSigningAlg != "" && alg != client.RequestObjectSigningAlg {
		return false
	}
	switch alg {
	case "none":
		return parts[2] == "" && kid == ""
	case "RS256":
		signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
		if err != nil || strings.ContainsAny(parts[2], "\r\n") {
			return false
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		for _, key := range client.RequestObjectKeys {
			if kid != "" && key.KeyID != kid {
				continue
			}
			pub, err := key.publicKey()
			if err == nil && rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil {
				return true
			}
		}
	}
	return false
}
