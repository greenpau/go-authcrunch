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
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestJWKSAdminMalformedTokenClaims(t *testing.T) {
	ks := newJWKSStore(t)
	signer := ks.GetSignKeys()[0]
	for _, field := range []string{"iss", "mail", "email", "sub", "name", "jti"} {
		for _, expired := range []bool{false, true} {
			name := field + "/current"
			if expired {
				name = field + "/expired"
			}
			t.Run(name, func(t *testing.T) {
				for _, value := range []any{123, nil, []string{"unexpected"}, map[string]any{"unexpected": true}} {
					exp := time.Now().Add(time.Hour).Unix()
					if expired {
						exp = time.Now().Add(-time.Hour).Unix()
					}
					claims := jwtlib.MapClaims{"sub": "test-admin", "roles": []string{"authp/admin"}, "exp": exp}
					claims[field] = value
					token := jwtlib.NewWithClaims(jwtlib.GetSigningMethod(signer.Sign.Token.DefaultMethod), claims)
					signed, err := token.SignedString(signer.Sign.Secret)
					if err != nil {
						t.Fatal("could not sign synthetic token")
					}
					ar := requests.NewAuthorizationRequest()
					ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, signed
					usr, err := ks.ParseToken(ar)
					if err == nil || usr != nil {
						t.Fatal("malformed claims authorized a user")
					}
				}
			})
		}
	}
}

func FuzzJWKSAdminTokenParsing(f *testing.F) {
	cfg, err := NewCryptoKeyStoreConfig(nil)
	if err != nil {
		f.Fatal(err)
	}
	ks, err := NewCryptoKeyStore(cfg, zap.NewNop())
	if err != nil {
		f.Fatal(err)
	}
	for _, token := range []string{"", "a.b.c", "e30.e30.", "eyJhbGciOiJub25lIn0.eyJzdWIiOjEyMywiZXhwIjoxfQ.", "Bearer invalid"} {
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token string) {
		ar := requests.NewAuthorizationRequest()
		ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, token
		usr, err := ks.ParseToken(ar)
		// This corpus never receives a signing credential or a valid token.
		if usr != nil || err == nil {
			t.Fatal("untrusted fuzz input authorized a user")
		}
	})
}
