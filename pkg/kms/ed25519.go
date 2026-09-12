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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// golang-jwt implements Ed25519 under the EdDSA JOSE name. RFC 9864 adds a
// distinct Ed25519 name for the same primitive. Its method must return that
// exact name so parser algorithm allowlists continue to distinguish the two.
type signingMethodEd25519 struct{}

func init() {
	jwtlib.RegisterSigningMethod("Ed25519", func() jwtlib.SigningMethod {
		return &signingMethodEd25519{}
	})
}

func (*signingMethodEd25519) Alg() string { return "Ed25519" }

func (*signingMethodEd25519) Verify(data string, signature []byte, key any) error {
	return jwtlib.SigningMethodEdDSA.Verify(data, signature, key)
}

func (*signingMethodEd25519) Sign(data string, key any) ([]byte, error) {
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, jwtlib.ErrInvalidKeyType
	}
	if err := validateEd25519PrivateKey(private); err != nil {
		return nil, err
	}
	// Pure Ed25519 signs the original JWS input, without a prehash or context.
	return ed25519.Sign(private, []byte(data)), nil
}

func validateEd25519PrivateKey(key ed25519.PrivateKey) error {
	// Check length before Seed, Public, or Sign, which assume a valid key.
	if len(key) != ed25519.PrivateKeySize {
		return jwtlib.ErrInvalidKey
	}
	derived := ed25519.NewKeyFromSeed(key.Seed())
	if subtle.ConstantTimeCompare(key, derived) != 1 {
		return jwtlib.ErrInvalidKey
	}
	return nil
}

func (k *CryptoKey) signEd25519(method, data string) (interface{}, error) {
	if method != "EdDSA" && method != "Ed25519" {
		return nil, errors.ErrDataSigningFailed.WithArgs("Ed25519", "unsupported method")
	}
	signature, err := (&signingMethodEd25519{}).Sign(data, k.Sign.Secret)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func generateEd25519Key() ([]byte, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
