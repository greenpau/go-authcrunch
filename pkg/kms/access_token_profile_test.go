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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

func TestAccessTokenProfileStrictVerification(t *testing.T) {
	f := fixture.New(t, "https://login.example.test/auth")
	store := f.Store(t)
	header := map[string]any{"alg": "PS256", "typ": kms.AccessTokenType, "kid": "current"}
	good := f.Claims()
	good["precise"] = json.Number("9007199254740993")
	good["decimal"] = json.Number("0.12345678901234567890123456789")
	token := f.Token(t, good)
	claims, err := store.VerifyAccessToken(t.Context(), token)
	if err != nil || claims["precise"] != good["precise"] || claims["decimal"] != good["decimal"] {
		t.Fatal("valid exact-number grant rejected")
	}
	changes := map[string]func(map[string]any){"missing audience": func(c map[string]any) { delete(c, "aud") }, "broad audience": func(c map[string]any) { c["aud"] = []string{"api", "other"} }, "duplicate audience": func(c map[string]any) { c["aud"] = []string{"api", "api"} }, "wrong issuer": func(c map[string]any) { c["iss"] = "https://other.test" }, "empty subject": func(c map[string]any) { c["sub"] = "" }, "fractional iat": func(c map[string]any) { c["iat"] = json.Number("1.5") }, "string exp": func(c map[string]any) { c["exp"] = "9999999999" }, "overflow exp": func(c map[string]any) { c["exp"] = json.Number("9223372036854775808") }, "future iat": func(c map[string]any) { c["iat"] = time.Now().Unix() + 30 }, "future nbf": func(c map[string]any) { c["nbf"] = time.Now().Unix() + 30 }, "historical nbf": func(c map[string]any) { c["nbf"] = time.Now().Unix() - 60 }, "expired exact": func(c map[string]any) { c["exp"] = time.Now().Unix() }, "long lifetime": func(c map[string]any) { c["exp"] = time.Now().Unix() + 301 }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := f.Claims()
			change(c)
			raw := f.RawToken(t, fixture.JSON(t, header), fixture.JSON(t, c), 32, false)
			if _, err := store.VerifyAccessToken(t.Context(), raw); err == nil {
				t.Fatal("invalid signed claims accepted")
			}
		})
	}
	for name, change := range map[string]func(map[string]any){"wrong alg": func(h map[string]any) { h["alg"] = "RS256" }, "wrong purpose": func(h map[string]any) { h["typ"] = "JWT" }, "unknown kid": func(h map[string]any) { h["kid"] = "other" }, "critical extension": func(h map[string]any) { h["crit"] = []string{"x"} }, "remote jku": func(h map[string]any) { h["jku"] = "https://other.test/keys" }, "missing kid": func(h map[string]any) { delete(h, "kid") }} {
		t.Run(name, func(t *testing.T) {
			h := map[string]any{"alg": "PS256", "typ": kms.AccessTokenType, "kid": "current"}
			change(h)
			if _, err := store.VerifyAccessToken(t.Context(), f.RawToken(t, fixture.JSON(t, h), fixture.JSON(t, good), 32, false)); err == nil {
				t.Fatal("wrong header accepted")
			}
		})
	}
	for name, raw := range map[string]string{"duplicate header": f.RawToken(t, []byte(`{"alg":"PS256","alg":"PS256","typ":"authcrunch-access+jwt","kid":"current"}`), fixture.JSON(t, good), 32, false), "duplicate nested": f.RawToken(t, fixture.JSON(t, header), []byte(strings.TrimSuffix(string(fixture.JSON(t, good)), "}")+`,"nested":{"x":1,"x":2}}`), 32, false), "max salt": f.RawToken(t, fixture.JSON(t, header), fixture.JSON(t, good), rsa.PSSSaltLengthAuto, false), "short salt": f.RawToken(t, fixture.JSON(t, header), fixture.JSON(t, good), 16, false), "same key RS256": f.RawToken(t, fixture.JSON(t, map[string]any{"alg": "RS256", "typ": kms.AccessTokenType, "kid": "current"}), fixture.JSON(t, good), 32, true), "padded": token + "="} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.VerifyAccessToken(t.Context(), raw); err == nil {
				t.Fatal("invalid signed envelope accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.VerifyAccessToken(ctx, token); err == nil {
		t.Fatal("canceled verifier accepted")
	}
	for _, source := range []string{"bearer", "basicauth", "apiauth"} {
		ar := requests.NewAuthorizationRequest()
		ar.Token.Payload = token
		ar.Token.Source = source
		if _, err := store.ParseToken(ar); err != nil {
			t.Fatal("existing token source rejected")
		}
	}
	for _, source := range []string{"unknown", "cookie", "header", "query"} {
		ar := requests.NewAuthorizationRequest()
		ar.Token.Payload = token
		ar.Token.Source = source
		ar.Token.Name = "unconfigured"
		if _, err := store.ParseToken(ar); err == nil {
			t.Fatal("unconfigured token source accepted")
		}
	}
}
func TestAccessTokenProfileCanonicalConfiguration(t *testing.T) {
	for _, issuer := range []string{"https://login.example.test", "https://login.example.test/auth", "https://127.0.0.1:8443/nested/auth", "https://[::1]:8443/auth"} {
		c := &kms.AccessTokenProfileConfig{Issuer: issuer, Audience: "api", KeyIDs: []string{"z", "a"}, MaxLifetimeSeconds: 300}
		original := c.KeyIDs
		if err := c.Validate(); err != nil || original[0] != "z" || c.KeyIDs[0] != "a" {
			t.Fatal("canonical profile or detached sorting failed")
		}
	}
	for _, issuer := range []string{"opaque", "http://login.test", "https://LOGIN.test/auth", "https://login.test/", "https://login.test/auth/", "https://login.test/a/../auth", "https://login.test/%61uth", "https://u:p@login.test/auth", "https://login.test/auth?x=1", "https://login.test/auth#x", "https://login.test:99999/auth", "https://login.test:0443/auth"} {
		c := &kms.AccessTokenProfileConfig{Issuer: issuer, Audience: "api", KeyIDs: []string{"current"}, MaxLifetimeSeconds: 300}
		if c.Validate() == nil {
			t.Fatal("noncanonical issuer accepted")
		}
	}
	f := fixture.New(t, "https://login.test/auth")
	cfg := f.CryptoConfig()
	cfg.AccessTokenProfile.Audience = ""
	cfg.RawKeyConfigs = []string{"crypto key current verify from file /must-not-open/access.pem"}
	if _, err := kms.NewCryptoKeyStore(cfg, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatal("profile was not checked before key access")
	}
	cfg = f.CryptoConfig()
	cfg.RawKeyConfigs = nil
	if _, err := kms.NewCryptoKeyStore(cfg, zap.NewNop()); err == nil {
		t.Fatal("strict profile generated fallback keys")
	}
	cfg = f.CryptoConfig()
	cfg.AccessTokenProfile.KeyIDs = []string{"missing"}
	if _, err := kms.NewCryptoKeyStore(cfg, zap.NewNop()); err == nil {
		t.Fatal("missing profile key accepted")
	}
	// Discovery is derived from captured trusted RSA keys and cannot expose private fields.
	store := f.Store(t)
	public, err := store.AccessTokenJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.Unmarshal(public, &jwks) != nil || len(jwks.Keys) != 1 || len(jwks.Keys[0]) != 6 {
		t.Fatal("public profile discovery malformed")
	}
	if jwks.Keys[0]["n"] != base64.RawURLEncoding.EncodeToString(f.Key.N.Bytes()) || jwks.Keys[0]["alg"] != "PS256" {
		t.Fatal("discovery differs from verifier")
	}
}

func TestAccessTokenProfileRetiringAndCapturedKeys(t *testing.T) {
	current := fixture.New(t, "https://login.test/auth")
	retired := fixture.New(t, "https://login.test/auth")
	unrelated := fixture.New(t, "https://login.test/auth")
	cfg := current.CryptoConfig()
	cfg.AccessTokenProfile.KeyIDs = []string{"retiring", "current"}
	cfg.RawKeyConfigs = append(cfg.RawKeyConfigs, "crypto key retiring verify from file "+retired.PublicFile, "crypto key unrelated verify from file "+unrelated.PublicFile)
	store, err := kms.NewCryptoKeyStore(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	old := retired.RawToken(t, fixture.JSON(t, map[string]any{"alg": "PS256", "typ": kms.AccessTokenType, "kid": "retiring"}), fixture.JSON(t, retired.Claims()), 32, false)
	unknown := unrelated.RawToken(t, fixture.JSON(t, map[string]any{"alg": "PS256", "typ": kms.AccessTokenType, "kid": "unrelated"}), fixture.JSON(t, unrelated.Claims()), 32, false)
	if _, err := store.VerifyAccessToken(t.Context(), old); err != nil {
		t.Fatal("explicit retiring key rejected")
	}
	if _, err := store.VerifyAccessToken(t.Context(), unknown); err == nil {
		t.Fatal("unprofiled key provided fallback authority")
	}
	public, err := store.AccessTokenJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.Unmarshal(public, &keys) != nil || len(keys.Keys) != 2 || keys.Keys[0]["kid"] != "current" || keys.Keys[1]["kid"] != "retiring" {
		t.Fatal("JWKS includes unrelated keys or lacks deterministic profile order")
	}
	trust := store.AccessTokenTrust()
	if err := os.WriteFile(current.PublicFile, []byte("invalid replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if store.AccessTokenTrust() != trust {
		t.Fatal("fingerprint reopened key file")
	}
	if _, err := store.VerifyAccessToken(t.Context(), current.Token(t, current.Claims())); err != nil {
		t.Fatal("captured verifier was changed by file replacement")
	}
	// Even, correctly-sized RSA moduli are not acceptable policy-only authority.
	cfg = retired.CryptoConfig()
	even := new(big.Int).Set(retired.Key.N)
	even.SetBit(even, 0, 0)
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: even, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retired.PublicFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := kms.NewCryptoKeyStore(cfg, zap.NewNop()); err == nil {
		t.Fatal("even RSA verifier accepted")
	}
}
