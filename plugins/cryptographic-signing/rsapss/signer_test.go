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

package rsapss_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	signing "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
)

func TestConfigValidation(t *testing.T) {
	if (*signing.Config)(nil).Validate() == nil {
		t.Fatal("nil config accepted")
	}
	good := testConfig("private.pem")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if good.Algorithm != "PS256" || good.MaxLifetime != "15m" {
		t.Fatal("incorrect defaults")
	}
	cases := map[string]func(*signing.Config){
		"missing file":     func(c *signing.Config) { c.KeyFile = "" },
		"empty kid":        func(c *signing.Config) { c.KeyID = "" },
		"unsafe kid":       func(c *signing.Config) { c.KeyID = "key/../../secret" },
		"long kid":         func(c *signing.Config) { c.KeyID = strings.Repeat("x", 129) },
		"missing issuer":   func(c *signing.Config) { c.Issuer = "" },
		"missing audience": func(c *signing.Config) { c.Audience = "" },
		"control":          func(c *signing.Config) { c.Issuer = "https://secret\n" },
		"whitespace":       func(c *signing.Config) { c.Audience = " api" },
		"invalid UTF8":     func(c *signing.Config) { c.KeyFile = "secret\xff" },
		"wrong algorithm":  func(c *signing.Config) { c.Algorithm = "RS256" },
		"unsupported PSS":  func(c *signing.Config) { c.Algorithm = "PS384" },
		"zero lifetime":    func(c *signing.Config) { c.MaxLifetime = "0s" },
		"fraction":         func(c *signing.Config) { c.MaxLifetime = "1.5s" },
		"long lifetime":    func(c *signing.Config) { c.MaxLifetime = "25h" },
		"invalid duration": func(c *signing.Config) { c.MaxLifetime = "secret" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := *good
			change(&c)
			err := c.Validate()
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("invalid config accepted or disclosed")
			}
		})
	}
	for _, duration := range []string{"1s", "24h"} {
		c := *good
		c.MaxLifetime = duration
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignerPreservesClaimsAndOwnership(t *testing.T) {
	_, path, _ := testKey(t, 2048)
	cfg := testConfig(path)
	signer, err := signing.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Algorithm != "" || cfg.MaxLifetime != "" {
		t.Fatal("constructor changed caller config")
	}
	cfg.KeyID = "changed"
	cfg.Issuer = "changed"
	cfg.MaxLifetime = "1s"
	claims := testClaims()
	claims["custom"] = map[string]any{"large": json.Number("9007199254740993"), "fraction": json.Number("1.25"), "boolean": true, "null": nil, "list": []any{"text", 42, false}, "typed_nil": []string(nil), "uint": uint64(math.MaxUint64)}
	original, _ := json.Marshal(claims)
	token, err := signer.Sign(t.Context(), claims)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPS256(token, jwks, testConfig(path).Issuer, "key-v1"); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !bytes.Equal(payload, original) {
		t.Fatal("signed claims changed")
	}
	after, _ := json.Marshal(claims)
	if !bytes.Equal(after, original) {
		t.Fatal("caller claims changed")
	}
	clear(jwks)
	fresh, _ := signer.PublicJWKS()
	if !json.Valid(fresh) {
		t.Fatal("JWKS aliases caller bytes")
	}
	writeTestFile(t, path, []byte("invalid replacement"))
	if next, err := signing.New(testConfig(path)); err == nil || next != nil {
		t.Fatal("bad reload published")
	}
	claims["custom"] = "later mutation"
	next, err := signer.Sign(t.Context(), claims)
	if err != nil {
		t.Fatal("active snapshot changed after file replacement")
	}
	if next == token {
		t.Fatal("new claims reused old token")
	}
	if _, err := verifyPS256(token, fresh, testConfig(path).Issuer, "key-v1"); err != nil {
		t.Fatal("old token changed after mutation")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 3 {
				tok, err := signer.Sign(t.Context(), claims)
				if err != nil {
					t.Error(err)
					return
				}
				keys, _ := signer.PublicJWKS()
				if _, err := verifyPS256(tok, keys, testConfig(path).Issuer, "key-v1"); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func TestSignerRejectsInvalidKeys(t *testing.T) {
	key, path, pubPath := testKey(t, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	writeTestFile(t, path, pkcs1)
	signer, err := signing.New(testConfig(path))
	if err != nil {
		t.Fatal("PKCS#1 rejected")
	}
	token, err := signer.Sign(t.Context(), testClaims())
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPS256(token, jwks, testConfig(path).Issuer, "key-v1"); err != nil {
		t.Fatal("PKCS#1 signature failed independent verification")
	}
	public, _ := os.ReadFile(pubPath)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	weak, _, _ := testKey(t, 1024)
	cases := map[string][]byte{
		"empty": nil, "garbage": []byte("secret-key"), "public only": public,
		"trailing":         append(append([]byte(nil), pkcs1...), []byte("secret-key")...),
		"multiple":         append(append([]byte(nil), pkcs1...), pkcs1...),
		"prefix":           append([]byte("secret-key\n"), pkcs1...),
		"oversize":         bytes.Repeat([]byte("x"), 16385),
		"invalid DER":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key")}),
		"encrypted header": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key), Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}}),
		"wrong key type":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER}),
		"too small":        pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			writeTestFile(t, path, data)
			next, err := signing.New(testConfig(path))
			if err == nil || next != nil || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "secret-key") {
				t.Fatal("invalid key accepted or disclosed")
			}
		})
	}
	for name, p := range map[string]string{"missing": filepath.Join(t.TempDir(), "secret-key"), "directory": t.TempDir()} {
		t.Run(name, func(t *testing.T) {
			if s, err := signing.New(testConfig(p)); err == nil || s != nil {
				t.Fatal("invalid path accepted")
			}
		})
	}
	// The target must be a valid private key so only the symlink causes rejection.
	writeTestFile(t, path, pkcs1)
	if _, err := signing.New(testConfig(path)); err != nil {
		t.Fatal("symlink target is not a valid private key")
	}
	link := filepath.Join(t.TempDir(), "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if s, err := signing.New(testConfig(link)); err == nil || s != nil {
		t.Fatal("symlink accepted")
	}
	if s, err := signing.New(nil); err == nil || s != nil {
		t.Fatal("nil config accepted")
	}
}

func TestSignerRejectsClaims(t *testing.T) {
	_, path, _ := testKey(t, 2048)
	signer, err := signing.New(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	cycle := map[string]any{}
	cycle["loop"] = cycle
	var depth any = "end"
	for range 16 {
		depth = []any{depth}
	}
	cases := map[string]func(map[string]any){
		"wrong issuer":       func(c map[string]any) { c["iss"] = "secret-issuer" },
		"object issuer":      func(c map[string]any) { c["iss"] = map[string]any{} },
		"empty subject":      func(c map[string]any) { c["sub"] = "" },
		"wrong audience":     func(c map[string]any) { c["aud"] = "other" },
		"multiple audiences": func(c map[string]any) { c["aud"] = []string{"api", "other"} },
		"object audience":    func(c map[string]any) { c["aud"] = []any{map[string]any{}} },
		"missing exp":        func(c map[string]any) { delete(c, "exp") },
		"expired":            func(c map[string]any) { c["exp"] = time.Now().Unix() - 1 },
		"future iat":         func(c map[string]any) { c["iat"] = time.Now().Unix() + 60 },
		"future nbf":         func(c map[string]any) { c["nbf"] = time.Now().Unix() + 60 },
		"nbf before iat":     func(c map[string]any) { c["nbf"] = c["iat"].(int64) - 1 },
		"long lifetime":      func(c map[string]any) { c["exp"] = c["iat"].(int64) + 901 },
		"fraction time":      func(c map[string]any) { c["iat"] = json.Number("1.5") },
		"string time":        func(c map[string]any) { c["iat"] = "123" },
		"overflow time":      func(c map[string]any) { c["iat"] = uint64(math.MaxUint64) },
		"zero time":          func(c map[string]any) { c["iat"] = 0 },
		"nan":                func(c map[string]any) { c["secret"] = math.NaN() },
		"infinity":           func(c map[string]any) { c["secret"] = float32(math.Inf(1)) },
		"invalid number":     func(c map[string]any) { c["secret"] = json.Number("null") },
		"struct":             func(c map[string]any) { c["secret"] = time.Now() },
		"binary":             func(c map[string]any) { c["secret"] = []byte("text") },
		"invalid utf8":       func(c map[string]any) { c["secret"] = "\xff" },
		"invalid key utf8":   func(c map[string]any) { c["\xff"] = true },
		"long string":        func(c map[string]any) { c["secret"] = strings.Repeat("s", 4097) },
		"nodes":              func(c map[string]any) { c["secret"] = make([]any, 4096) },
		"depth":              func(c map[string]any) { c["secret"] = depth },
		"cycle":              func(c map[string]any) { c["secret"] = cycle },
		"claims count": func(c map[string]any) {
			for i := range 129 {
				c[strings.Repeat("x", i+1)] = true
			}
		},
		"aggregate text": func(c map[string]any) {
			c["secret"] = strings.Split(strings.Repeat(strings.Repeat("s", 4096)+",", 17), ",")
		},
		"encoded size": func(c map[string]any) {
			c["secret"] = strings.Split(strings.Repeat(strings.Repeat("\x00", 4000)+",", 8), ",")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			claims := testClaims()
			change(claims)
			token, err := signer.Sign(t.Context(), claims)
			if err == nil || token != "" || strings.Contains(err.Error(), "secret") {
				t.Fatal("invalid claims accepted or disclosed")
			}
		})
	}
	for _, claims := range []map[string]any{nil, {}} {
		if tok, err := signer.Sign(t.Context(), claims); err == nil || tok != "" {
			t.Fatal("empty claims accepted")
		}
	}
	// A string audience is also a valid single-audience JWT representation.
	claims := testClaims()
	claims["aud"] = "api"
	if _, err := signer.Sign(t.Context(), claims); err != nil {
		t.Fatal(err)
	}
}

type lateCancelContext struct {
	context.Context
	calls int
}

func (c *lateCancelContext) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.Canceled
	}
	return nil
}

func TestSignerCancellationAndZeroValue(t *testing.T) {
	_, path, _ := testKey(t, 2048)
	signer, err := signing.New(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, release := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer release()
	for _, ctx := range []context.Context{canceled, expired, &lateCancelContext{Context: t.Context()}} {
		token, err := signer.Sign(ctx, testClaims())
		if token != "" || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
			t.Fatal("canceled signing returned a token")
		}
	}
	var missing context.Context
	if token, err := signer.Sign(missing, testClaims()); err == nil || token != "" {
		t.Fatal("nil context accepted")
	}
	for _, s := range []*signing.Signer{nil, {}} {
		if token, err := s.Sign(t.Context(), testClaims()); err == nil || token != "" {
			t.Fatal("uninitialized signer accepted")
		}
		if keys, err := s.PublicJWKS(); err == nil || keys != nil {
			t.Fatal("uninitialized JWKS accepted")
		}
	}
}
