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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newEd25519Files(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("could not generate test key")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("could not encode test private key")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("could not encode test public key")
	}
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	for path, block := range map[string]*pem.Block{
		privatePath: {Type: "PRIVATE KEY", Bytes: privateDER},
		publicPath:  {Type: "PUBLIC KEY", Bytes: publicDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return private, privatePath, publicPath
}

// Independent producer: no KMS or golang-jwt signing implementation is used.
func ed25519TestToken(t *testing.T, private ed25519.PrivateKey, method string, claims any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": method, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	data := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return data + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(data)))
}

func verifyEd25519TestToken(t *testing.T, public ed25519.PublicKey, token, method string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("expected a compact JWS")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal("invalid header encoding")
	}
	var metadata map[string]string
	if err := json.Unmarshal(header, &metadata); err != nil || metadata["alg"] != method {
		t.Fatal("incorrect JWT algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("independent Ed25519 verification failed")
	}
}

func TestEd25519SigningAndVerification(t *testing.T) {
	private, privatePath, publicPath := newEd25519Files(t)
	signer := newJWKSStore(t, "crypto key sign-verify from file "+privatePath)
	verifier := newJWKSStore(t, "crypto key verify from file "+publicPath)
	for _, method := range []string{"EdDSA", "Ed25519"} {
		t.Run(method, func(t *testing.T) {
			u := newJWKSUser(t)
			if err := signer.SignToken(nil, method, u); err != nil {
				t.Fatal(err)
			}
			verifyEd25519TestToken(t, private.Public().(ed25519.PublicKey), u.Token, method)
			ar := requests.NewAuthorizationRequest()
			ar.Token.Source = tokenSourceBearerHeader
			for _, signed := range []string{u.Token, ed25519TestToken(t, private, method, map[string]any{"sub": "external", "exp": time.Now().Add(time.Hour).Unix()})} {
				ar.Token.Payload = signed
				if usr, err := verifier.ParseToken(ar); err != nil || usr == nil {
					t.Fatal("public-only store rejected valid token")
				}
			}
			// A registration that aliases Ed25519 to an EdDSA object would
			// incorrectly pass the other name's allowlist here.
			other := "EdDSA"
			if method == other {
				other = "Ed25519"
			}
			for _, allowed := range []string{method, other} {
				token, err := jwtlib.Parse(u.Token, verifier.GetVerifyKeys()[0].ProvideKey, jwtlib.WithValidMethods([]string{allowed}))
				if allowed == method {
					if err != nil || !token.Valid || token.Method.Alg() != method {
						t.Fatal("exact method allowlist rejected token")
					}
				} else if err == nil {
					t.Fatal("different method allowlist accepted token")
				}
			}
			keyUser := newJWKSUser(t)
			if err := signer.GetSignKeys()[0].SignToken(method, keyUser); err != nil {
				t.Fatal(err)
			}
			verifyEd25519TestToken(t, private.Public().(ed25519.PublicKey), keyUser.Token, method)
			if err := verifier.SignToken(nil, method, newJWKSUser(t)); err == nil {
				t.Fatal("public key signed a token")
			}
		})
	}
	u := newJWKSUser(t)
	if err := signer.SignToken(nil, nil, u); err != nil {
		t.Fatal(err)
	}
	verifyEd25519TestToken(t, private.Public().(ed25519.PublicKey), u.Token, "EdDSA")
	for _, method := range []string{"eddsa", "ED25519", "Ed448", "HS256", "ES256"} {
		if err := signer.SignToken(nil, method, newJWKSUser(t)); err == nil {
			t.Fatal("unsupported method signed a token")
		}
	}
}

func TestEd25519ExistingKeySourcesAndUsage(t *testing.T) {
	_, privatePath, publicPath := newEd25519Files(t)
	data, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTHCRUNCH_TEST_ED_PEM", string(data))
	t.Setenv("AUTHCRUNCH_TEST_ED_FILE", privatePath)
	// Keep only the private file in the directory to make its derived kid unambiguous.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Signing.Key.pem"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTHCRUNCH_TEST_ED_DIR", dir)
	for _, source := range []string{
		"from file " + privatePath,
		"from env AUTHCRUNCH_TEST_ED_PEM",
		"from env AUTHCRUNCH_TEST_ED_PEM as key",
		"from env AUTHCRUNCH_TEST_ED_FILE as file",
		"from directory " + dir,
		"from env AUTHCRUNCH_TEST_ED_DIR as directory",
	} {
		for _, usage := range []string{"sign", "verify", "sign-verify", "auto"} {
			t.Run(source+"/"+usage, func(t *testing.T) {
				ks := newJWKSStore(t, "crypto key "+usage+" "+source)
				key := ks.GetKeys()[0]
				if key.Config.Algorithm != "ed25519" || key.Sign.Capable != (usage != "verify") || key.Verify.Capable != (usage != "sign") {
					t.Fatal("incorrect key capabilities")
				}
				if len(ks.GetSignKeys()) != 0 {
					u := newJWKSUser(t)
					if err := ks.SignToken(nil, nil, u); err != nil {
						t.Fatal(err)
					}
					parsed, _, err := jwtlib.NewParser().ParseUnverified(u.Token, jwtlib.MapClaims{})
					if err != nil {
						t.Fatal("could not inspect token")
					}
					if strings.Contains(source, "directory") && parsed.Header["kid"] != "signingkey" {
						t.Fatal("directory key ID changed")
					}
					if !strings.Contains(source, "directory") && parsed.Header["kid"] != nil {
						t.Fatal("unnamed key acquired a kid")
					}
				}
				if usage == "verify" {
					if data, err := ks.GetJWKS(); err != nil || data != nil {
						t.Fatal("verification key was published as issuer")
					}
					if data, err := ks.GetJWKSPrivateKeys("", ""); err != nil || data != nil {
						t.Fatal("verification credential was exported")
					}
				}
			})
		}
	}
	for _, cfg := range []*CryptoKeyConfig{
		{Source: "config", Usage: "sign-verify", Algorithm: "ed25519", FilePath: privatePath},
		{Source: "config", Usage: "verify", Algorithm: "ed25519", FilePath: publicPath},
	} {
		if err := cfg.validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := GetKeysFromConfig(cfg); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := GetKeysFromConfig(&CryptoKeyConfig{Source: "config", Usage: "sign", FilePath: publicPath}); err == nil {
		t.Fatal("public key accepted for sign-only usage")
	}
	if _, err := GetKeysFromConfig(&CryptoKeyConfig{Source: "generate", Usage: "sign-verify", Algorithm: "ed25519", ID: t.Name()}); err != nil {
		t.Fatal(err)
	}
}

func TestEd25519RejectsInvalidTokens(t *testing.T) {
	private, _, publicPath := newEd25519Files(t)
	wrong, _, _ := newEd25519Files(t)
	ks := newJWKSStore(t, "crypto key verify from file "+publicPath)
	for _, method := range []string{"EdDSA", "Ed25519"} {
		claims := map[string]any{"sub": "external", "exp": time.Now().Add(time.Hour).Unix()}
		good := ed25519TestToken(t, private, method, claims)
		parts := strings.Split(good, ".")
		wrongLabel := "EdDSA"
		if method == wrongLabel {
			wrongLabel = "Ed25519"
		}
		header, _ := json.Marshal(map[string]string{"alg": wrongLabel})
		alteredHeader := base64.RawURLEncoding.EncodeToString(header) + "." + parts[1] + "." + parts[2]
		cases := map[string]string{
			"wrong key":        ed25519TestToken(t, wrong, method, claims),
			"changed header":   alteredHeader,
			"changed body":     parts[0] + ".e30." + parts[2],
			"short signature":  parts[0] + "." + parts[1] + ".AA",
			"long signature":   good + "AAAA",
			"unsigned":         parts[0] + "." + parts[1] + ".",
			"lowercase method": ed25519TestToken(t, private, strings.ToLower(method), claims),
			"wrong curve":      ed25519TestToken(t, private, "Ed448", claims),
			"none":             ed25519TestToken(t, private, "none", claims),
			"expired":          ed25519TestToken(t, private, method, map[string]any{"sub": "external", "exp": time.Now().Add(-time.Hour).Unix()}),
			"malformed claims": ed25519TestToken(t, private, method, map[string]any{"sub": 123, "exp": time.Now().Add(time.Hour).Unix()}),
		}
		hmac := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims(claims))
		confusion, err := hmac.SignedString([]byte(private.Public().(ed25519.PublicKey)))
		if err != nil {
			t.Fatal(err)
		}
		cases["HMAC public key confusion"] = confusion
		for name, signed := range cases {
			t.Run(method+"/"+name, func(t *testing.T) {
				ar := requests.NewAuthorizationRequest()
				ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, signed
				if u, err := ks.ParseToken(ar); err == nil || u != nil {
					t.Fatal("invalid token authorized a user")
				}
			})
		}
	}
}

func TestEd25519InvalidKeyMaterial(t *testing.T) {
	private, path, publicPath := newEd25519Files(t)
	mismatch := append(ed25519.PrivateKey(nil), private...)
	mismatch[len(mismatch)-1] ^= 1
	for i, value := range []any{nil, ed25519.PrivateKey(nil), ed25519.PrivateKey{1}, make(ed25519.PrivateKey, 65), mismatch, []byte(private)} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ks := newJWKSStore(t, "crypto key sign-verify from file "+path)
			ks.GetSignKeys()[0].Sign.Secret = value
			for _, method := range []string{"EdDSA", "Ed25519"} {
				if err := ks.SignToken(nil, method, newJWKSUser(t)); err == nil {
					t.Fatal("invalid signing key accepted")
				}
			}
			if data, err := ks.GetJWKS(); err == nil || data != nil {
				t.Fatal("invalid signing key published")
			}
			if data, err := ks.GetJWKSPrivateKeys("", ""); err == nil || data != nil {
				t.Fatal("invalid signing key exported")
			}
			if _, err := jwtlib.GetSigningMethod("Ed25519").Sign("test", value); err == nil {
				t.Fatal("registered method accepted invalid private key")
			}
		})
	}
	for _, value := range []any{nil, ed25519.PublicKey(nil), ed25519.PublicKey{1}, make(ed25519.PublicKey, 33), []byte(private.Public().(ed25519.PublicKey))} {
		ks := newJWKSStore(t, "crypto key verify from file "+publicPath)
		ks.GetVerifyKeys()[0].Verify.Secret = value
		for _, method := range []string{"EdDSA", "Ed25519"} {
			ar := requests.NewAuthorizationRequest()
			ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, ed25519TestToken(t, private, method, map[string]any{"sub": "external"})
			if u, err := ks.ParseToken(ar); err == nil || u != nil {
				t.Fatal("invalid public key accepted")
			}
		}
	}
}

func TestEd25519GenerationSharing(t *testing.T) {
	// Sharing a tag shares only material. Each store keeps its requested label,
	// and both verifiers accept either label regardless of generation order.
	for _, order := range [][]string{{"EdDSA", "Ed25519"}, {"Ed25519", "EdDSA"}} {
		t.Run(strings.Join(order, "_"), func(t *testing.T) {
			stores := make([]*CryptoKeyStore, 2)
			var wg sync.WaitGroup
			for i, method := range order {
				wg.Go(func() {
					cfg, err := NewCryptoKeyStoreConfig([]string{"crypto default autogenerate tag " + t.Name(), "crypto default autogenerate algorithm " + method})
					if err != nil {
						t.Error(err)
						return
					}
					stores[i], err = NewCryptoKeyStore(cfg, zap.NewNop())
					if err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			if t.Failed() {
				return
			}
			for i, ks := range stores {
				u := newJWKSUser(t)
				if err := ks.SignToken(nil, nil, u); err != nil {
					t.Fatal(err)
				}
				for _, verifier := range stores {
					public := verifier.GetVerifyKeys()[0].Verify.Secret.(ed25519.PublicKey)
					verifyEd25519TestToken(t, public, u.Token, order[i])
					ar := requests.NewAuthorizationRequest()
					ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, u.Token
					if _, err := verifier.ParseToken(ar); err != nil {
						t.Fatal("shared key could not verify other label")
					}
				}
			}
		})
	}
	for _, order := range [][]string{{"ES512", "EdDSA"}, {"Ed25519", "ES512"}} {
		t.Run(strings.Join(order, "_"), func(t *testing.T) {
			for i, method := range order {
				cfg := &CryptoKeyStoreConfig{AutoGenerateTag: t.Name(), AutoGenerateAlgo: method}
				_, err := NewCryptoKeyStore(cfg, zap.NewNop())
				if (err != nil) != (i == 1) {
					t.Fatal("incompatible generation tag was reused")
				}
			}
		})
	}
	for _, method := range []string{"eddsa", "ED25519", "Ed448"} {
		if _, err := NewCryptoKeyStore(&CryptoKeyStoreConfig{AutoGenerateTag: t.Name(), AutoGenerateAlgo: method}, zap.NewNop()); err == nil {
			t.Fatal("unsupported generation algorithm accepted")
		}
	}
}

func TestEd25519PreservesExistingSigners(t *testing.T) {
	_, privatePath, publicPath := newEd25519Files(t)
	type signerCase struct {
		methods   []string
		directive string
	}
	cases := []signerCase{
		{[]string{"HS512", "HS384", "HS256"}, "crypto key existing sign-verify synthetic-ed-compatibility-secret"},
		{[]string{"RS512", "RS384", "RS256"}, "crypto key existing sign-verify from file ../../testdata/rskeys/test_2_pri.pem"},
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "existing.pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		method := map[string]string{"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[curve.Params().Name]
		cases = append(cases, signerCase{[]string{method}, "crypto key existing sign-verify from file " + path})
	}
	for _, tc := range cases {
		t.Run(tc.methods[0], func(t *testing.T) {
			for _, verifierPath := range []string{publicPath, privatePath} {
				ks := newJWKSStore(t,
					"crypto key internal system 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"crypto key foreign verify from file "+verifierPath, tc.directive,
					"crypto key existing token name original_access_token",
					"crypto key existing token lifetime 1800",
					"crypto key later sign-verify from file "+privatePath,
					"crypto key later token name ed_access_token",
					"crypto key later token lifetime 600")
				for _, method := range append([]string{""}, tc.methods...) {
					var requested any
					want := tc.methods[0]
					if method != "" {
						requested, want = method, method
					}
					u := newJWKSUser(t)
					if err := ks.SignToken(nil, requested, u); err != nil {
						t.Fatal(err)
					}
					token, err := jwtlib.Parse(u.Token, func(*jwtlib.Token) (any, error) {
						for _, k := range ks.GetVerifyKeys() {
							if k.Config.ID == "existing" {
								return k.Verify.Secret, nil
							}
						}
						return nil, fmt.Errorf("original verification key missing")
					}, jwtlib.WithValidMethods([]string{want}), jwtlib.WithExpirationRequired())
					if err != nil || !token.Valid || token.Header["kid"] != "existing" || u.TokenName != "original_access_token" {
						t.Fatal("existing signer, signature, or token name changed")
					}
					if ks.GetTokenLifetime(nil, requested) != 1800 {
						t.Fatal("existing token lifetime changed")
					}
					ar := requests.NewAuthorizationRequest()
					ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, u.Token
					if _, err := ks.ParseToken(ar); err != nil {
						t.Fatal("mixed store rejected the original signing method")
					}
				}
				// Explicit algorithms retain the existing first-eligible-key
				// contract; they must not silently switch to a later signer.
				if err := ks.SignToken(nil, "Ed25519", newJWKSUser(t)); err == nil {
					t.Fatal("explicit method silently changed key ordering")
				}
				// Selecting a later token by its existing name still selects
				// that token's key and lifetime, including the new key family.
				u := newJWKSUser(t)
				if err := ks.SignToken("ed_access_token", "Ed25519", u); err != nil {
					t.Fatal(err)
				}
				if u.TokenName != "ed_access_token" || ks.GetTokenLifetime("ed_access_token", "Ed25519") != 600 {
					t.Fatal("named token selection changed")
				}
			}
		})
	}
	cfg, err := NewCryptoKeyStoreConfig(nil)
	if err != nil || cfg.AutoGenerateAlgo != "ES512" {
		t.Fatal("default generation changed")
	}
	cfg.AutoGenerateTag = t.Name()
	ks, err := NewCryptoKeyStore(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if ks.GetSignKeys()[0].Sign.Token.DefaultMethod != "ES512" {
		t.Fatal("default signing changed")
	}
}

func TestEd25519JWKSExports(t *testing.T) {
	for _, method := range []string{"EdDSA", "Ed25519"} {
		t.Run(method, func(t *testing.T) {
			ks := newJWKSStore(t, "crypto default autogenerate tag "+t.Name(), "crypto default autogenerate algorithm "+method)
			data, err := ks.GetJWKS()
			if err != nil {
				t.Fatal(err)
			}
			var public struct {
				Keys []map[string]string `json:"keys"`
			}
			if err := json.Unmarshal(data, &public); err != nil || len(public.Keys) != 1 {
				t.Fatal("invalid public JWKS array")
			}
			key := public.Keys[0]
			if len(key) != 5 || key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["alg"] != method || key["use"] != "sig" {
				t.Fatal("invalid Ed25519 public JWK")
			}
			pub, err := base64.RawURLEncoding.DecodeString(key["x"])
			if err != nil || len(pub) != ed25519.PublicKeySize {
				t.Fatal("invalid public key encoding")
			}
			for _, format := range []string{"pkcs8", "jwk"} {
				encodings := []string{"pem", "der"}
				if format == "jwk" {
					encodings = []string{"json"}
				}
				for _, encoding := range encodings {
					exported, err := ks.GetJWKSPrivateKeys(format, encoding)
					if err != nil {
						t.Fatal(err)
					}
					var result struct {
						Keys []jwksPrivateKey `json:"keys"`
					}
					if err := json.Unmarshal(exported, &result); err != nil || len(result.Keys) != 1 {
						t.Fatal("invalid private export array")
					}
					var private ed25519.PrivateKey
					if format == "jwk" {
						var jwk map[string]string
						if err := json.Unmarshal(result.Keys[0].PrivateKey, &jwk); err != nil || len(jwk) != 6 {
							t.Fatal("invalid private JWK")
						}
						seed, err := base64.RawURLEncoding.DecodeString(jwk["d"])
						if err != nil || len(seed) != ed25519.SeedSize {
							t.Fatal("private JWK must encode a 32-byte seed")
						}
						private = ed25519.NewKeyFromSeed(seed)
					} else {
						var value string
						if err := json.Unmarshal(result.Keys[0].PrivateKey, &value); err != nil {
							t.Fatal("invalid encoded private key")
						}
						var der []byte
						if encoding == "pem" {
							block, rest := pem.Decode([]byte(value))
							if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
								t.Fatal("invalid PKCS8 PEM")
							}
							der = block.Bytes
						} else {
							der, err = base64.StdEncoding.DecodeString(value)
							if err != nil {
								t.Fatal("invalid PKCS8 DER encoding")
							}
						}
						parsed, err := x509.ParsePKCS8PrivateKey(der)
						if err != nil {
							t.Fatal("invalid PKCS8 key")
						}
						var ok bool
						private, ok = parsed.(ed25519.PrivateKey)
						if !ok {
							t.Fatal("wrong exported key type")
						}
					}
					if !bytes.Equal(pub, private.Public().(ed25519.PublicKey)) {
						t.Fatal("private and public exports differ")
					}
					signed := ed25519TestToken(t, private, method, map[string]any{"sub": "export-consumer"})
					ar := requests.NewAuthorizationRequest()
					ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, signed
					if _, err := ks.ParseToken(ar); err != nil {
						t.Fatal("exported private key cannot sign usable tokens")
					}
				}
			}
			for _, format := range []string{"pkcs1", "sec1"} {
				if data, err := ks.GetJWKSPrivateKeys(format, ""); err == nil || data != nil {
					t.Fatal("incompatible private format accepted")
				}
			}
		})
	}
}

func TestEd25519RFC8037Vector(t *testing.T) {
	// RFC 8037 Appendix A.4/A.5 is an independent, fixed JWS test vector.
	// https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.4
	const input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	const signature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	seed, err := base64.RawURLEncoding.DecodeString("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	k := newCryptoKey()
	k.Sign.Secret = ed25519.NewKeyFromSeed(seed)
	for _, method := range []string{"EdDSA", "Ed25519"} {
		// Test the primitive on the fixed input; changing its header would
		// require a different signature, as covered by the parser tests.
		got, err := k.signEd25519(method, input)
		if err != nil || got != input+"."+signature {
			t.Fatal("signer does not match RFC 8037 vector")
		}
		if err := jwtlib.GetSigningMethod(method).Verify(input, sig, ed25519.PublicKey(public)); err != nil {
			t.Fatal("verifier rejected RFC 8037 vector")
		}
	}
}

func FuzzEd25519TokenParsing(f *testing.F) {
	// Stable material lets coordinator and worker processes share valid seeds.
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		f.Fatal(err)
	}
	keys, err := GetKeysFromConfig(&CryptoKeyConfig{Source: "env", Usage: "verify", EnvVarType: "key", EnvVarValue: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	if err != nil {
		f.Fatal(err)
	}
	ks := &CryptoKeyStore{}
	if err := ks.AddKeys(keys); err != nil {
		f.Fatal(err)
	}

	for _, method := range []string{"EdDSA", "Ed25519"} {
		header, _ := json.Marshal(map[string]string{"alg": method})
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"fuzz-consumer"}`))
		f.Add(input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input))))
	}
	f.Add("a.b.c")
	f.Add("e30.e30.")
	f.Fuzz(func(t *testing.T, signed string) {
		ar := requests.NewAuthorizationRequest()
		ar.Token.Source, ar.Token.Payload = tokenSourceBearerHeader, signed
		u, err := ks.ParseToken(ar)
		if err != nil {
			return
		}
		if u == nil {
			t.Fatal("successful parse returned no user")
		}
		parts := strings.Split(signed, ".")
		if len(parts) != 3 {
			t.Fatal("authorized malformed compact JWT")
		}
		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal("authorized invalid header encoding")
		}
		var metadata map[string]any
		if err := json.Unmarshal(header, &metadata); err != nil || (metadata["alg"] != "EdDSA" && metadata["alg"] != "Ed25519") {
			t.Fatal("authorized unexpected algorithm")
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
			t.Fatal("authorized an independently invalid signature")
		}
	})
}
