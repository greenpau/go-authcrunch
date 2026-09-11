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

// Package refresh manages rotating credentials independently of access JWTs.
package refresh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const tokenPrefix = "acr1_"

var (
	// ErrInvalid indicates an unknown, expired, revoked, or replayed credential.
	ErrInvalid = errors.New("invalid refresh credential")
	// ErrDenied indicates a definitive identity or authentication-policy denial.
	ErrDenied = errors.New("refresh requires reauthentication")
	// ErrUnavailable indicates a temporary failure; the current token is unspent.
	ErrUnavailable = errors.New("refresh temporarily unavailable")
)

func randomID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func newToken() (string, [32]byte, error) {
	var b [32]byte
	_, err := rand.Read(b[:])
	s := tokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	return s, sha256.Sum256([]byte(s)), err
}

func digest(s string) ([32]byte, error) {
	if !strings.HasPrefix(s, tokenPrefix) || len(s) != len(tokenPrefix)+43 {
		return [32]byte{}, ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s[len(tokenPrefix):])
	if err != nil || len(b) != 32 {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256([]byte(s)), nil
}
