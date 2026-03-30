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
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	// "golang.org/x/crypto/chacha20poly1305"
)

// Encryptor represents system messaging subsystem.
type Encryptor struct {
	keyID string
	key   []byte
}

// NewEncryptor returns an instance of Encryptor.
func NewEncryptor(keyID string, key []byte) (*Encryptor, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key id is empty")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}
	return &Encryptor{
		keyID: keyID,
		key:   key,
	}, nil
}

// NewEncryptorFromKey reads a hex-encoded private key file and decodes it.
func NewEncryptorFromKey(keyID, filePath string) (*Encryptor, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	hexString := strings.TrimSpace(string(content))

	key, err := ParseKeyFromString(hexString)
	if err != nil {
		return nil, err
	}

	return NewEncryptor(keyID, key)
}

// ParseKeyFromString parses shared secret from hex encoded string.
func ParseKeyFromString(hexString string) ([]byte, error) {
	key, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	return key, nil
}

// GetKeyID returns key ID associated with the Encryptor.
func (enc *Encryptor) GetKeyID() string {
	return enc.keyID
}
