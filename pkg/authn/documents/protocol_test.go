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

package documents_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

// The checked-in vector was emitted by the portable Web Crypto module. This
// independent Go consumer verifies its vault, key agreement, KDF, AAD and tags.
func TestProtocolWebCryptoInteroperability(t *testing.T) {
	raw, err := os.ReadFile("testdata/protocol.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Bootstrap struct {
			Portal string `json:"portal_id"`
			UserID string `json:"user_id"`
		}
		Registration          documents.Key
		Recovery              string `json:"recoveryKey"`
		File                  documents.File
		Plaintext, Ciphertext string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatal("vector encoding")
		}
		return b
	}
	ctx := func(parts ...string) []byte {
		b, _ := json.Marshal(append([]string{documents.Protocol}, parts...))
		return b
	}
	open := func(material, salt, info, nonce, ciphertext []byte) []byte {
		key, err := hkdf.Key(sha256.New, material, salt, string(info), 32)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		result, err := aead.Open(nil, nonce, ciphertext, info)
		if err != nil {
			t.Fatal("independent vector authentication failed")
		}
		return result
	}
	vault := v.Registration.Vault
	scalar := open(decode(v.Recovery), decode(vault.Salt), ctx("vault", v.Bootstrap.Portal, v.Bootstrap.UserID, v.Registration.KeyID), decode(vault.Nonce), decode(vault.Ciphertext))
	private, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.PublicKey().Bytes(), decode(v.Registration.PublicKey)) {
		t.Fatal("vault private/public mismatch")
	}
	ephemeral, err := ecdh.P256().NewPublicKey(decode(v.File.Envelope.EphemeralKey))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	fileCtx := func(purpose string, extra ...string) []byte {
		return ctx(append([]string{purpose, v.Bootstrap.Portal, v.File.Owner, v.File.ID, strconv.FormatInt(v.File.Size, 10), strconv.Itoa(v.File.Chunks)}, extra...)...)
	}
	salt := sha256.Sum256([]byte(documents.Protocol))
	nonce := make([]byte, 12)
	key := open(shared, salt[:], fileCtx("envelope", v.Bootstrap.UserID, v.Registration.KeyID, v.File.Envelope.EphemeralKey), nonce, decode(v.File.Envelope.Ciphertext))
	plain := open(key, salt[:], fileCtx("chunk", "0"), nonce, decode(v.Ciphertext))
	if !bytes.Equal(plain, decode(v.Plaintext)) {
		t.Fatal("independent plaintext mismatch")
	}
	metadata := open(key, salt[:], fileCtx("metadata"), nonce, decode(v.File.Metadata))
	var name struct{ Name string }
	if json.Unmarshal(metadata, &name) != nil || name.Name != "private-report.txt" {
		t.Fatal("metadata interoperability failed")
	}
}
