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
	"path/filepath"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

func TestPersistentGeneratedKeys(t *testing.T) {
	for _, algorithm := range []string{"ES512", "EdDSA", "Ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "state")
			open := func() (*CryptoKeyStore, *state.Store) {
				s, err := state.Open(&state.Config{Directory: directory})
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := NewCryptoKeyStoreConfig([]string{"crypto default autogenerate algorithm " + algorithm})
				if err != nil {
					t.Fatal(err)
				}
				cfg.SetStateStore(s)
				ks, err := NewCryptoKeyStore(cfg, zap.NewNop())
				if err != nil {
					t.Fatal(err)
				}
				return ks, s
			}
			first, s := open()
			u := newJWKSUser(t)
			if err := first.SignToken(nil, nil, u); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			second, s := open()
			defer s.Close()
			token, err := jwtlib.Parse(u.Token, second.GetVerifyKeys()[0].ProvideKey)
			if err != nil || !token.Valid {
				t.Fatal("restart changed signing key")
			}
			other, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "other")})
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			cfg, _ := NewCryptoKeyStoreConfig([]string{"crypto default autogenerate algorithm " + algorithm})
			cfg.SetStateStore(other)
			independent, err := NewCryptoKeyStore(cfg, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := jwtlib.Parse(u.Token, independent.GetVerifyKeys()[0].ProvideKey); err == nil {
				t.Fatal("independent state directories shared generated keys")
			}
		})
	}
}
