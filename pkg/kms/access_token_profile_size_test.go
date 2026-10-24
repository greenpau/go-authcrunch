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

package kms_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

func TestAccessTokenProfileEnvelopeSizeBoundaries(t *testing.T) {
	f := fixture.New(t, "https://login.example.test/auth")
	store := f.Store(t)
	header := fixture.JSON(t, map[string]any{"alg": "PS256", "typ": kms.AccessTokenType, "kid": "current"})
	payload := fixture.JSON(t, f.Claims())
	pad := func(t *testing.T, document []byte, size int) []byte {
		t.Helper()
		if size < len(document) {
			t.Fatal("invalid boundary fixture size")
		}
		// JSON whitespace expands the signed document without changing any
		// claim, member count, nesting level or string-value limit.
		return []byte(string(document) + strings.Repeat(" ", size-len(document)))
	}
	assert := func(t *testing.T, h, p []byte, accepted bool) string {
		t.Helper()
		raw := f.RawToken(t, h, p, 32, false)
		// Independently verify every envelope, including negative controls:
		// denial must not merely reflect a bad signature in the fixture.
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatal("boundary fixture is not a compact signed envelope")
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err != nil || rsa.VerifyPSS(&f.Key.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}) != nil {
			t.Fatal("boundary fixture signature is invalid")
		}
		claims, err := store.VerifyAccessToken(t.Context(), raw)
		if accepted {
			if err != nil || claims["sub"] != "alice" {
				t.Fatal("valid boundary envelope rejected")
			}
		} else if err == nil || claims != nil {
			t.Fatal("oversized envelope returned authenticated claims")
		}
		return raw
	}
	for _, tc := range []struct {
		name                      string
		headerBytes, payloadBytes int
		accepted                  bool
	}{
		{"ordinary", len(header), len(payload), true},
		{"header_exact", 1024, len(payload), true},
		{"header_over", 1025, len(payload), false},
		{"payload_exact", len(header), 64 << 10, true},
		{"payload_over", len(header), (64 << 10) + 1, false},
		{"both_inner_limits", 1024, 64 << 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := pad(t, header, tc.headerBytes), pad(t, payload, tc.payloadBytes)
			raw := assert(t, h, p, tc.accepted)
			if len(raw) >= 96<<10 {
				t.Fatal("inner-limit fixture unexpectedly reaches the compact wrapper cap")
			}
		})
	}

	// No accepted token can reach the conservative 96 KiB compact cap:
	// even an 8192-bit RSA signature with both maximum inner documents is
	// smaller. These independently valid signatures exercise exact and
	// over-cap rejection; their payloads necessarily also exceed 64 KiB.
	// The accepted both_inner_limits case is the corresponding reachable
	// positive control. Do not claim these negatives isolate the early guard.
	for _, tc := range []struct {
		name string
		size int
	}{{"compact_exact", 96 << 10}, {"compact_over", (96 << 10) + 1}} {
		t.Run(tc.name, func(t *testing.T) {
			for headerSize := len(header); headerSize < len(header)+3; headerSize++ {
				encodedPayload := tc.size - base64.RawURLEncoding.EncodedLen(headerSize) - base64.RawURLEncoding.EncodedLen(f.Key.Size()) - 2
				payloadSize := base64.RawURLEncoding.DecodedLen(encodedPayload)
				if base64.RawURLEncoding.EncodedLen(payloadSize) != encodedPayload {
					continue
				}
				if payloadSize <= 64<<10 {
					t.Fatal("compact boundary fixture contradicts inner document limits")
				}
				raw := assert(t, pad(t, header, headerSize), pad(t, payload, payloadSize), false)
				if len(raw) != tc.size {
					t.Fatal("compact boundary fixture has the wrong exact size")
				}
				return
			}
			t.Fatal("could not construct the exact compact boundary fixture")
		})
	}
}
