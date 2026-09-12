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

package oauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func newOAuthEdKey(t *testing.T, id, alg string) (*JwksKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := &JwksKey{KeyID: id, Algorithm: alg, KeyType: "OKP", Curve: "Ed25519", CoordX: base64.RawURLEncoding.EncodeToString(public), PublicKeyUse: "sig"}
	if err := key.validatePublicKey(); err != nil {
		t.Fatal(err)
	}
	return key, private
}

func oauthTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Use the standard library over the exact JWS bytes, independently of the
// production method registration and signing adapter.
func signOAuthEdToken(t *testing.T, private ed25519.PrivateKey, header map[string]any, claims jwtlib.MapClaims) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(oauthTestJSON(t, header)) + "." + base64.RawURLEncoding.EncodeToString(oauthTestJSON(t, claims))
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
}

func oauthEdClaims() jwtlib.MapClaims {
	return jwtlib.MapClaims{"sub": "ed-user", "email": "ed@example.com", "name": "Ed User", "nonce": "ed-nonce", "iss": oauthValidatorTestIssuer, "aud": oauthValidatorTestClientID, "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"viewer"}}
}

func oauthEdProvider(t *testing.T, keys ...*JwksKey) *IdentityProvider {
	t.Helper()
	b := &IdentityProvider{config: &Config{ClientID: oauthValidatorTestClientID, Issuer: oauthValidatorTestIssuer, Driver: "generic", IdentityTokenFieldName: "id_token"}, keys: newOAuthJwksSet(keys), state: newStateManager()}
	if err := b.state.add("ed-state", "ed-nonce"); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOAuthEd25519JWK(t *testing.T) {
	key, _ := newOAuthEdKey(t, "ed-key", "")
	for _, alg := range []string{"", "EdDSA", "Ed25519"} {
		copy := *key
		copy.Algorithm = alg
		if err := copy.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, ok := copy.GetPublic().(ed25519.PublicKey); !ok {
			t.Fatal("untyped Ed25519 key")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*JwksKey)
	}{
		{"missing kid", func(k *JwksKey) { k.KeyID = "" }},
		{"curve", func(k *JwksKey) { k.Curve = "Ed448" }},
		{"X25519", func(k *JwksKey) { k.Curve = "X25519" }},
		{"missing curve", func(k *JwksKey) { k.Curve = "" }},
		{"algorithm", func(k *JwksKey) { k.Algorithm = "HS256" }},
		{"algorithm case", func(k *JwksKey) { k.Algorithm = "eddsa" }},
		{"encryption use", func(k *JwksKey) { k.PublicKeyUse = "enc" }},
		{"sign only", func(k *JwksKey) { k.KeyOperations = []string{"sign"} }},
		{"empty operations", func(k *JwksKey) { k.KeyOperations = []string{} }},
		{"duplicate operations", func(k *JwksKey) { k.KeyOperations = []string{"verify", "verify"} }},
		{"contradictory operations", func(k *JwksKey) { k.KeyOperations = []string{"verify", "encrypt"} }},
		{"unknown operations", func(k *JwksKey) { k.KeyOperations = []string{"verify", "unknown"} }},
		{"missing x", func(k *JwksKey) { k.CoordX = "" }},
		{"malformed x", func(k *JwksKey) { k.CoordX = "%%%" }},
		{"padded x", func(k *JwksKey) { k.CoordX += "=" }},
		{"newline x", func(k *JwksKey) { k.CoordX += "\n" }},
		{"short x", func(k *JwksKey) { k.CoordX = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) }},
		{"long x", func(k *JwksKey) { k.CoordX = base64.RawURLEncoding.EncodeToString(make([]byte, 33)) }},
		{"y", func(k *JwksKey) { k.CoordY = "AA" }},
		{"modulus", func(k *JwksKey) { k.Modulus = "AA" }},
		{"exponent", func(k *JwksKey) { k.Exponent = "AQAB" }},
		{"secret", func(k *JwksKey) { k.SharedSecret = "AA" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *key
			tc.change(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("invalid Ed JWK accepted")
			}
			if copy.GetPublic() != nil {
				t.Fatal("failed revalidation retained usable key")
			}
		})
	}
	copy := *key
	copy.KeyOperations = []string{"sign", "verify"}
	copy.PublicKeyUse = ""
	copy.CoordX = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := copy.Validate(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copy.GetPublic().(ed25519.PublicKey), make([]byte, 32)) {
		t.Fatal("public octets lost leading zeroes")
	}
	if err := (*JwksKey)(nil).Validate(); err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestOAuthEd25519RemoteJWKMetadata(t *testing.T) {
	key, _ := newOAuthEdKey(t, "ed-key", "")
	for _, tc := range []struct {
		name, field string
		value       any
		valid       bool
	}{
		{"verify operations", "key_ops", []string{"verify"}, true},
		{"empty operations", "key_ops", []string{}, false},
		{"null operations", "key_ops", nil, false},
		{"operations type", "key_ops", "verify", false},
		{"private d", "d", "synthetic-private-value", false},
		{"null private d", "d", nil, false},
		{"empty y", "y", "", false},
		{"null algorithm", "alg", nil, false},
		{"empty algorithm", "alg", "", false},
		{"null use", "use", nil, false},
		{"empty use", "use", "", false},
		{"null kid", "kid", nil, false},
		{"numeric kid", "kid", 1, false},
		{"empty kid", "kid", "", false},
		{"unknown extension", "vendor_data", map[string]any{"a": 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]any
			json.Unmarshal(oauthTestJSON(t, key), &fields)
			fields[tc.field] = tc.value
			_, err := decodeOAuthJwk(oauthTestJSON(t, fields))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("private material leaked")
			}
		})
	}
	copy := *key
	copy.KeyID = ""
	if _, err := decodeOAuthJwk(oauthTestJSON(t, copy)); err != nil {
		t.Fatal("optional remote kid rejected")
	}
	if err := copy.Validate(); err == nil {
		t.Fatal("explicit public constructor lost required kid contract")
	}
}

func TestOAuthEd25519Algorithms(t *testing.T) {
	for _, jwkAlg := range []string{"", "EdDSA", "Ed25519"} {
		for _, tokenAlg := range []string{"EdDSA", "Ed25519"} {
			t.Run(jwkAlg+"/"+tokenAlg, func(t *testing.T) {
				key, private := newOAuthEdKey(t, "ed-key", jwkAlg)
				b := oauthEdProvider(t, key)
				token := signOAuthEdToken(t, private, map[string]any{"alg": tokenAlg, "kid": key.KeyID}, oauthEdClaims())
				claims, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": token, "access_token": "opaque"})
				want := jwkAlg == "" || jwkAlg == tokenAlg
				if (err == nil) != want {
					t.Fatalf("accept=%v: %v", want, err)
				}
				if want && claims["sub"] != "ed-user" {
					t.Fatal("identity claims not extracted")
				}
			})
		}
	}
}

func TestOAuthEd25519TrustClaims(t *testing.T) {
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		for _, tc := range []struct {
			name   string
			mutate func(jwtlib.MapClaims)
		}{
			{"issuer", func(c jwtlib.MapClaims) { c["iss"] = "https://wrong.example" }},
			{"audience", func(c jwtlib.MapClaims) { c["aud"] = "wrong" }},
			{"authorized party", func(c jwtlib.MapClaims) { c["azp"] = "wrong" }},
			{"multi audience missing azp", func(c jwtlib.MapClaims) { c["aud"] = []string{oauthValidatorTestClientID, "other"} }},
			{"nonce", func(c jwtlib.MapClaims) { c["nonce"] = "wrong" }},
			{"numeric nonce", func(c jwtlib.MapClaims) { c["nonce"] = 42 }},
			{"missing nonce", func(c jwtlib.MapClaims) { delete(c, "nonce") }},
			{"expiry", func(c jwtlib.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
			{"not before", func(c jwtlib.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
			{"malformed time", func(c jwtlib.MapClaims) { c["exp"] = "later" }},
			{"missing email", func(c jwtlib.MapClaims) { delete(c, "email") }},
			{"name types", func(c jwtlib.MapClaims) { delete(c, "name"); c["given_name"] = 1; c["family_name"] = "User" }},
		} {
			t.Run(alg+"/"+tc.name, func(t *testing.T) {
				key, private := newOAuthEdKey(t, "ed-key", alg)
				b := oauthEdProvider(t, key)
				claims := oauthEdClaims()
				tc.mutate(claims)
				token := signOAuthEdToken(t, private, map[string]any{"alg": alg, "kid": key.KeyID}, claims)
				if _, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": token}); err == nil {
					t.Fatal("invalid identity accepted")
				}
			})
		}
	}
}

func TestOAuthEd25519AccessTokenClaims(t *testing.T) {
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		key, private := newOAuthEdKey(t, "ed-key", alg)
		b := oauthEdProvider(t, key)
		header := map[string]any{"alg": alg, "kid": key.KeyID}
		id := signOAuthEdToken(t, private, header, oauthEdClaims())
		accessClaims := oauthEdClaims()
		delete(accessClaims, "nonce")
		accessClaims["roles"] = []string{"editor"}
		accessClaims["aud"] = "resource"
		accessClaims["azp"] = oauthValidatorTestClientID
		access := signOAuthEdToken(t, private, header, accessClaims)
		claims, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": id, "access_token": access})
		if err != nil || !reflect.DeepEqual(claims["roles"], []string{"viewer", "editor"}) {
			t.Fatal("verified access claims did not merge", err)
		}
		_, rogue := newOAuthEdKey(t, "rogue", alg)
		for _, bad := range []string{"opaque", signOAuthEdToken(t, rogue, header, accessClaims), unsignedOAuthValidatorTestToken(t, accessClaims)} {
			claims, err = b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": id, "access_token": bad})
			if err != nil || !reflect.DeepEqual(claims["roles"], []string{"viewer"}) {
				t.Fatal("unverified access claims affected identity", err)
			}
		}
		b.config.IdentityTokenFieldName = "access_token"
		if _, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"access_token": id}); err != nil {
			t.Fatal("selected identity access token rejected", err)
		}
		if _, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"access_token": access}); err == nil {
			t.Fatal("identity access token bypassed nonce")
		}
	}
}

func TestOAuthEd25519PublicPEM(t *testing.T) {
	key, private := newOAuthEdKey(t, "pem-key", "")
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ed.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewJwksKeyFromPublicKeyPEM(key.KeyID, path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.GetPublic().(ed25519.PublicKey), key.GetPublic().(ed25519.PublicKey)) {
		t.Fatal("PEM changed key")
	}
	if _, err := NewJwksKeyFromRSAPublicKeyPEM(key.KeyID, path); err == nil {
		t.Fatal("RSA-specific API accepted Ed key")
	}
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		b := oauthEdProvider(t, loaded)
		token := signOAuthEdToken(t, private, map[string]any{"alg": alg, "kid": key.KeyID}, oauthEdClaims())
		if _, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": token}); err != nil {
			t.Fatal(err)
		}
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{[]byte("not PEM"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewJwksKeyFromPublicKeyPEM(key.KeyID, path); err == nil {
			t.Fatal("invalid public PEM accepted")
		}
	}
	if _, err := NewJwksKeyFromPublicKeyPEM(key.KeyID, path+"missing"); err == nil {
		t.Fatal("missing PEM accepted")
	}
}

func TestOAuthEd25519RFC8037PublicKey(t *testing.T) {
	// RFC 8037 A.2/A.4/A.5 supplies the public JWK and independent signature.
	// Its payload is not JSON claims, so exercise key ingestion and the primitive.
	const input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	const encodedSignature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	key, err := decodeOAuthJwk([]byte(`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		candidates := newOAuthJwksSet([]*JwksKey{key}).verificationKeys(alg, "", false)
		if len(candidates.Keys) != 1 || jwtlib.GetSigningMethod(alg).Verify(input, signature, candidates.Keys[0]) != nil {
			t.Fatal("public JWK failed the RFC verification vector")
		}
	}
}
