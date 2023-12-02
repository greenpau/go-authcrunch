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

package tests

import (
	"crypto/rand"
	"github.com/google/uuid"
	"io"
	mathrand "math/rand"
	"strings"
)

// NewID returns a random ID to be used for user identification.
func NewID() string {
	return uuid.New().String()
}

// NewRandomString returns a random string.
func NewRandomString(length int) string {
	chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	charsLen := byte(36)

	if length == 0 {
		length = 32
	}

	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		var sb strings.Builder
		for i := 0; i < length; i++ {
			sb.WriteRune(chars[mathrand.Intn(len(chars))])
		}
		return sb.String()
	}

	for i, char := range b {
		b[i] = byte(chars[char%charsLen])
	}

	return string(b)
}
