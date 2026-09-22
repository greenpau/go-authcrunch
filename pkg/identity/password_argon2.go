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

package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Lengths participate in the work profile as well as memory, passes and lanes.
type argon2Parameters struct {
	memory, iterations, parallelism, saltSize, keySize int
}

type argon2Hash struct {
	parameters argon2Parameters
	salt, key  []byte
}

func deriveArgon2(candidate, salt []byte, p argon2Parameters) []byte {
	// Callers validate the work profile. Keep constant bounds at the narrowing
	// conversions too, so unsupported parameters cannot reach the KDF.
	if p.iterations < 1 || p.iterations > maxArgon2Iterations ||
		p.memory < 8 || p.memory > maxArgon2Memory ||
		p.parallelism < 1 || p.parallelism > maxArgon2Parallelism ||
		p.keySize < 16 || p.keySize > 64 {
		return nil
	}
	return argon2.IDKey(candidate, salt, uint32(p.iterations), uint32(p.memory), uint8(p.parallelism), uint32(p.keySize))
}

func generateArgon2(candidate string, c *PasswordHashConfig) string {
	p := argon2Parameters{c.Memory, c.Iterations, c.Parallelism, argon2SaltSize, argon2KeySize}
	salt := make([]byte, p.saltSize)
	rand.Read(salt)
	key := deriveArgon2([]byte(candidate), salt, p)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		p.memory, p.iterations, p.parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// parseArgon2 validates the entire PHC string before any expensive operation.
// Only Argon2id v19 is supported. Errors never include credential material.
func parseArgon2(encoded string) (*argon2Hash, error) {
	invalid := fmt.Errorf("invalid argon2id password hash")
	if len(encoded) > 256 {
		return nil, invalid
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, invalid
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, invalid
	}
	var values [3]int
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], prefix) {
			return nil, invalid
		}
		value := strings.TrimPrefix(params[i], prefix)
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 || strconv.Itoa(n) != value {
			return nil, invalid
		}
		values[i] = n
	}
	if err := validateArgon2Parameters(values[0], values[1], values[2]); err != nil {
		return nil, err
	}
	// Canonical unpadded base64 also rejects CR/LF accepted by Go's decoder.
	decode := func(s string, minSize int) ([]byte, error) {
		b, err := base64.RawStdEncoding.Strict().DecodeString(s)
		if err != nil || len(b) < minSize || len(b) > 64 || base64.RawStdEncoding.EncodeToString(b) != s {
			return nil, invalid
		}
		return b, nil
	}
	salt, err := decode(parts[4], 8)
	if err != nil {
		return nil, err
	}
	key, err := decode(parts[5], 16)
	if err != nil {
		return nil, err
	}
	return &argon2Hash{parameters: argon2Parameters{values[0], values[1], values[2], len(salt), len(key)}, salt: salt, key: key}, nil
}

func (h *argon2Hash) match(candidate string) bool {
	key := deriveArgon2([]byte(candidate), h.salt, h.parameters)
	return subtle.ConstantTimeCompare(key, h.key) == 1
}
