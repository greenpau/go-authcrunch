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

// Package jwtutil provides the exact Ed25519 JOSE method shared by JWT consumers.
package jwtutil

import (
	"crypto/ed25519"
	"crypto/subtle"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// RFC 9864 names the same primitive as EdDSA with crv Ed25519. Keep the
// method name distinct: changing a signed header would invalidate its signature.
type signingMethodEd25519 struct{}

func init() {
	jwtlib.RegisterSigningMethod("Ed25519", Ed25519)
}

// Ed25519 returns the method for the fully specified Ed25519 JOSE name.
func Ed25519() jwtlib.SigningMethod { return &signingMethodEd25519{} }

func (*signingMethodEd25519) Alg() string { return "Ed25519" }

func (*signingMethodEd25519) Verify(data string, signature []byte, key any) error {
	return jwtlib.SigningMethodEdDSA.Verify(data, signature, key)
}

func (*signingMethodEd25519) Sign(data string, key any) ([]byte, error) {
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, jwtlib.ErrInvalidKeyType
	}
	if err := ValidateEd25519PrivateKey(private); err != nil {
		return nil, err
	}
	// Pure Ed25519 signs the original JWS input, without a prehash or context.
	return ed25519.Sign(private, []byte(data)), nil
}

// IsEd25519Method recognizes only the two concrete supported implementations.
func IsEd25519Method(method jwtlib.SigningMethod) bool {
	switch m := method.(type) {
	case *jwtlib.SigningMethodEd25519:
		return m != nil && m.Alg() == "EdDSA"
	case *signingMethodEd25519:
		return m != nil && m.Alg() == "Ed25519"
	default:
		return false
	}
}

// ValidateEd25519PrivateKey checks both length and seed/public-key consistency.
func ValidateEd25519PrivateKey(key ed25519.PrivateKey) error {
	// Seed, Public, and Sign assume a valid key; check its length first.
	if len(key) != ed25519.PrivateKeySize {
		return jwtlib.ErrInvalidKey
	}
	derived := ed25519.NewKeyFromSeed(key.Seed())
	if subtle.ConstantTimeCompare(key, derived) != 1 {
		return jwtlib.ErrInvalidKey
	}
	return nil
}
