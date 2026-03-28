// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package system

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptMessage handles message encryption with PASETO v4.local construction.
// It marshals the input data to JSON, generates a random 24-byte nonce,
// and encrypts the payload using XChaCha20-Poly1305.
func (e *Encryptor) EncryptMessage(data interface{}) (string, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	aead, err := chacha20poly1305.NewX(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	header := []byte("v4.local.")
	ciphertext := aead.Seal(nil, nonce, payload, header)

	tokenBody := append(nonce, ciphertext...)
	encodedBody := base64.RawURLEncoding.EncodeToString(tokenBody)
	encodedFooter := base64.RawURLEncoding.EncodeToString([]byte(e.keyID))
	return "v4.local." + encodedBody + "." + encodedFooter, nil
}

// DecryptMessage handles message decryption for a PASETO v4.local token.
// It validates the header, decodes the body, extracts the nonce, and decrypts the payload.
func (e *Encryptor) DecryptMessage(token string, data interface{}) error {
	header := "v4.local."
	if !strings.HasPrefix(token, header) {
		return fmt.Errorf("invalid token header: expected %s", header)
	}

	parts := strings.Split(token, ".")
	// Expecting 4 parts: [v4, local, body, footer]
	if len(parts) != 4 {
		return fmt.Errorf("invalid token format: expected 4 segments, got %d", len(parts))
	}

	encodedBody := parts[2]
	encodedFooter := parts[3]

	footerBytes, err := base64.RawURLEncoding.DecodeString(encodedFooter)
	if err != nil {
		return fmt.Errorf("failed to decode footer: %w", err)
	}

	keyID := string(footerBytes)
	if keyID != e.keyID {
		return fmt.Errorf("key id mismatch: expected %s, got %s", e.keyID, keyID)
	}

	tokenBody, err := base64.RawURLEncoding.DecodeString(encodedBody)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(tokenBody) < 40 {
		return fmt.Errorf("token body too short")
	}

	nonce := tokenBody[:24]
	ciphertext := tokenBody[24:]

	aead, err := chacha20poly1305.NewX(e.key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(header))
	if err != nil {
		return fmt.Errorf("failed to decrypt or authenticate: %w", err)
	}

	if err := json.Unmarshal(plaintext, data); err != nil {
		return fmt.Errorf("failed to unmarshal plaintext: %w", err)
	}

	return nil
}
