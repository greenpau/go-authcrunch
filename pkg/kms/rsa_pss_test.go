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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestPS256Verification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	store := newJWKSStore(t, "crypto key verify from file "+path)
	claims := map[string]any{"sub": "alice", "email": "alice@example.test", "roles": []string{"viewer"}, "exp": time.Now().Add(time.Minute).Unix()}
	body, _ := json.Marshal(claims)
	makeToken := func(algorithm string, salt int, wrongKey bool) string {
		t.Helper()
		header, _ := json.Marshal(map[string]string{"alg": algorithm, "typ": "JWT"})
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
		digest := sha256.Sum256([]byte(input))
		private := key
		if wrongKey {
			private, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
		}
		sig, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: salt})
		if err != nil {
			t.Fatal(err)
		}
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	for _, tc := range []struct {
		name, algorithm string
		salt            int
		wrongKey, want  bool
	}{
		{"standard", "PS256", 32, false, true}, {"auto salt", "PS256", rsa.PSSSaltLengthAuto, false, false}, {"short salt", "PS256", 16, false, false}, {"wrong key", "PS256", 32, true, false}, {"relabeled RSA", "RS256", 32, false, false}, {"unsupported PSS", "PS384", 32, false, false}, {"none", "none", 32, false, false}, {"HMAC confusion", "HS256", 32, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ar := requests.NewAuthorizationRequest()
			ar.Token.Source = tokenSourceBearerHeader
			ar.Token.Payload = makeToken(tc.algorithm, tc.salt, tc.wrongKey)
			usr, err := store.ParseToken(ar)
			if (err == nil) != tc.want || tc.want && usr == nil {
				t.Fatalf("verification accepted=%t, want %t", err == nil, tc.want)
			}
		})
	}
	// Per-call strictness must not mutate the JWT dependency's global registration.
	if jwtlib.SigningMethodPS256.VerifyOptions.SaltLength != rsa.PSSSaltLengthAuto {
		t.Fatal("global PSS options changed")
	}
	legacy, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims(claims)).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	ar := requests.NewAuthorizationRequest()
	ar.Token.Source = tokenSourceBearerHeader
	ar.Token.Payload = legacy
	if _, err := store.ParseToken(ar); err != nil {
		t.Fatal("existing RSA verification regressed")
	}
}

func TestPS256VerifierRejectsInvalidKeyAndMethod(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []any{nil, (*rsa.PublicKey)(nil), &rsa.PublicKey{}, &weak.PublicKey, []byte("public bytes")} {
		token := &jwtlib.Token{Method: jwtlib.SigningMethodPS256, Header: map[string]any{"alg": "PS256"}}
		if err := preparePS256Verification(token, secret); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	for _, method := range []jwtlib.SigningMethod{jwtlib.SigningMethodPS384, jwtlib.SigningMethodPS512, jwtlib.SigningMethodHS256, (*jwtlib.SigningMethodRSAPSS)(nil), &jwtlib.SigningMethodRSAPSS{}, &jwtlib.SigningMethodRSAPSS{SigningMethodRSA: &jwtlib.SigningMethodRSA{Name: "PS256", Hash: crypto.SHA384}}} {
		token := &jwtlib.Token{Method: method, Header: map[string]any{"alg": "PS256"}}
		if err := preparePS256Verification(token, &key.PublicKey); err == nil {
			t.Fatal("invalid algorithm accepted")
		}
	}
	if err := preparePS256Verification(&jwtlib.Token{Method: jwtlib.SigningMethodPS256, Header: map[string]any{"alg": "RS256"}}, &key.PublicKey); err == nil {
		t.Fatal("mismatched header accepted")
	}
}
