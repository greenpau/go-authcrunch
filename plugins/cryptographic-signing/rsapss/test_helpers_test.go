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

package rsapss_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	signing "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
)

// Portable helpers are copied with the consumer into an external module.
func testKey(t *testing.T, bits int) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal("generate fixture key:", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode fixture private key")
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("encode fixture public key")
	}
	dir := t.TempDir()
	privPath, pubPath := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	writeTestFile(t, privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	writeTestFile(t, pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	return key, privPath, pubPath
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func testConfig(path string) *signing.Config {
	return &signing.Config{KeyFile: path, KeyID: "key-v1", Issuer: "https://issuer.example.test/auth", Audience: "api"}
}

func testClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": "https://issuer.example.test/auth", "sub": "alice", "aud": []string{"api"}, "iat": now, "nbf": now, "exp": now + 120, "roles": []string{"viewer"}}
}

// Verify independently with the standard library and fetched public JWK fields.
// No plugin or KMS verification implementation participates here.
func verifyPS256(token string, jwks []byte, issuer, kid string) (map[string]any, error) {
	invalid := func() (map[string]any, error) { return nil, fmt.Errorf("independent PS256 verification failed") }
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalid()
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return invalid()
	}
	var metadata map[string]string
	if json.Unmarshal(header, &metadata) != nil || metadata["alg"] != "PS256" || metadata["kid"] != kid || metadata["typ"] != signing.TokenType {
		return invalid()
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if json.Unmarshal(jwks, &set) != nil {
		return invalid()
	}
	var public *rsa.PublicKey
	for _, key := range set.Keys {
		if key["kid"] != kid {
			continue
		}
		if key["kty"] != "RSA" || key["alg"] != "PS256" || key["use"] != "sig" || len(key) != 6 {
			return invalid()
		}
		n, err := base64.RawURLEncoding.DecodeString(key["n"])
		if err != nil {
			return invalid()
		}
		e, err := base64.RawURLEncoding.DecodeString(key["e"])
		if err != nil {
			return invalid()
		}
		public = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if public == nil || public.N.BitLen() < 2048 {
		return invalid()
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return invalid()
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPSS(public, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: 32}) != nil {
		return invalid()
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var claims map[string]any
	if decoder.Decode(&claims) != nil || claims["iss"] != issuer || claims["sub"] != "alice" {
		return invalid()
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "api" {
		return invalid()
	}
	for _, name := range []string{"iat", "nbf", "exp"} {
		n, ok := claims[name].(json.Number)
		if !ok {
			return invalid()
		}
		value, err := n.Int64()
		if err != nil {
			return invalid()
		}
		if name == "exp" && value <= time.Now().Unix() || name != "exp" && value > time.Now().Unix() {
			return invalid()
		}
	}
	return claims, nil
}
