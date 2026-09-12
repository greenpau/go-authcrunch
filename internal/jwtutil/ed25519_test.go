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

package jwtutil_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/internal/jwtutil"
)

type disguisedMethod struct{ jwtlib.SigningMethod }

func (disguisedMethod) Alg() string { return "Ed25519" }

func TestEd25519Method(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"EdDSA", "Ed25519"} {
		t.Run(name, func(t *testing.T) {
			method := jwtlib.GetSigningMethod(name)
			if !jwtutil.IsEd25519Method(method) || method.Alg() != name {
				t.Fatal("incorrect JOSE registration")
			}
			input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"`+name+`"}`)) + ".e30"
			sig, err := method.Sign(input, private)
			if err != nil || !ed25519.Verify(public, []byte(input), sig) {
				t.Fatal("signature failed independent verification")
			}
			if err := method.Verify(input, ed25519.Sign(private, []byte(input)), public); err != nil {
				t.Fatal(err)
			}
			if err := method.Verify(input+"x", sig, public); err == nil {
				t.Fatal("tampered input verified")
			}
			for _, key := range []any{[]byte(public), ed25519.PublicKey{1}, private, nil} {
				if err := method.Verify(input, sig, key); err == nil {
					t.Fatal("invalid public key accepted")
				}
			}
			token := input + "." + base64.RawURLEncoding.EncodeToString(sig)
			if _, err := jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return public, nil }, jwtlib.WithValidMethods([]string{name})); err != nil {
				t.Fatal(err)
			}
			other := "EdDSA"
			if name == other {
				other = "Ed25519"
			}
			if _, err := jwtlib.Parse(token, func(*jwtlib.Token) (any, error) { return public, nil }, jwtlib.WithValidMethods([]string{other})); err == nil {
				t.Fatal("exact algorithm allowlist bypassed")
			}
		})
	}
	for _, method := range []jwtlib.SigningMethod{nil, (*jwtlib.SigningMethodEd25519)(nil), jwtlib.SigningMethodHS256, disguisedMethod{jwtlib.SigningMethodEdDSA}} {
		if jwtutil.IsEd25519Method(method) {
			t.Fatal("untrusted method accepted")
		}
	}
	bad := append(ed25519.PrivateKey(nil), private...)
	bad[len(bad)-1] ^= 1
	for _, key := range []any{nil, public, []byte(private), ed25519.PrivateKey{1}, bad} {
		if _, err := jwtutil.Ed25519().Sign("message", key); err == nil {
			t.Fatal("invalid signing material accepted")
		}
	}
}
