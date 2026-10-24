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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/kms"
	signing "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
)

func TestSignerMetadata(t *testing.T) {
	for _, signer := range []*signing.Signer{nil, {}} {
		metadata, err := signer.Metadata()
		if err == nil || metadata != (kms.AccessSignerMetadata{}) {
			t.Fatal("uninitialized signer returned metadata")
		}
	}
	_, path, _ := testKey(t, 2048)
	config := testConfig(path)
	config.MaxLifetime = "900s"
	signer, err := signing.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxLifetime != "900s" {
		t.Fatal("constructor mutated input")
	}
	normalized := *config
	if err := normalized.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	want := kms.AccessSignerMetadata{
		Kind: "rsapss", ConfigDigest: hex.EncodeToString(digest[:]),
		Policy: kms.AccessSignerPolicy{
			Algorithm: "PS256", KeyID: normalized.KeyID, TokenType: signing.TokenType,
			Issuer: normalized.Issuer, Audience: normalized.Audience, MaxLifetimeSeconds: 900,
		},
	}
	metadata, err := signer.Metadata()
	if err != nil || metadata != want {
		t.Fatal("signer metadata differs from normalized backend configuration")
	}
	declaration, err := kms.NewExternalAccessSignerConfig("different-host-name", "rsapss", want.Policy, normalized)
	if err != nil || declaration.ConfigDigest != metadata.ConfigDigest {
		t.Fatal("root assignment changed backend identity")
	}
	// A newly built equivalent spelling must attest the same frozen configuration.
	equivalent := *config
	equivalent.MaxLifetime = "15m0s"
	second, err := signing.New(&equivalent)
	if err != nil {
		t.Fatal(err)
	}
	secondMetadata, err := second.Metadata()
	if err != nil || secondMetadata != want {
		t.Fatal("equivalent lifetime changed metadata")
	}
	config.KeyID, config.KeyFile, config.Issuer = "changed", "missing", "changed"
	metadata.Policy.KeyID, metadata.ConfigDigest = "changed", "changed"
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	again, err := signer.Metadata()
	if err != nil || again != want {
		t.Fatal("metadata reread the key or retained mutable caller state")
	}
	token, err := signer.Sign(t.Context(), testClaims())
	if err != nil {
		t.Fatal(err)
	}
	public, err := signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPS256(token, public, want.Policy.Issuer, want.Policy.KeyID); err != nil {
		t.Fatal("metadata no longer describes the active signing key")
	}
}

func TestSignerNormalizedConfigurationIdentity(t *testing.T) {
	_, path, _ := testKey(t, 2048)
	base := testConfig(path)
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, duration := range []string{"", "15m", "900s", "15m0s", "0.25h"} {
		config := *base
		config.MaxLifetime = duration
		if err := config.Validate(); err != nil || config != *base {
			t.Fatal("equivalent duration did not normalize identically")
		}
		if err := config.Validate(); err != nil || config != *base {
			t.Fatal("validation is not idempotent")
		}
	}
	signer, err := signing.New(base)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := signer.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*signing.Config){
		"kid":      func(c *signing.Config) { c.KeyID = "other-kid" },
		"issuer":   func(c *signing.Config) { c.Issuer = "https://other.example.test/auth" },
		"audience": func(c *signing.Config) { c.Audience = "other-audience" },
		"lifetime": func(c *signing.Config) { c.MaxLifetime = "16m" },
	} {
		t.Run(name, func(t *testing.T) {
			config := *base
			change(&config)
			other, err := signing.New(&config)
			if err != nil {
				t.Fatal(err)
			}
			got, err := other.Metadata()
			if err != nil || got.ConfigDigest == metadata.ConfigDigest {
				t.Fatal("different configuration retained the prior backend identity")
			}
		})
	}
}

func TestSignerMetadataDoesNotRestrictStandaloneIssuer(t *testing.T) {
	_, path, _ := testKey(t, 2048)
	config := testConfig(path)
	config.Issuer = "opaque-standalone-issuer"
	signer, err := signing.New(config)
	if err != nil {
		t.Fatal("selected-profile rules changed the standalone constructor", err)
	}
	if _, err := signer.Metadata(); err == nil {
		t.Fatal("opaque issuer was accepted as strict root profile metadata")
	}
	claims := testClaims()
	claims["iss"] = config.Issuer
	token, err := signer.Sign(t.Context(), claims)
	if err != nil {
		t.Fatal("selected-profile rules changed standalone signing", err)
	}
	public, err := signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPS256(token, public, config.Issuer, config.KeyID); err != nil {
		t.Fatal("standalone token did not preserve its approved issuer")
	}
}
