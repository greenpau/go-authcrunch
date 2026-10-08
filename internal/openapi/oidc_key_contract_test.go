// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/kms"
	"go.uber.org/zap"
)

func TestRepositoryOIDCRefreshScope(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := SchemaAt(c, "/components/schemas/OIDCRefreshScope")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", false}, {" \t\n\u0085\u2003", false}, {"openid", true},
		{"\u0085openid\u2003profile\u00a0", true}, {"offline_access phone", true},
		{"\ufeffopenid", false}, {"openid,profile", false}, {"unregistered", false},
	} {
		if (scope.Validate(tc.value) == nil) != tc.valid {
			t.Errorf("scope contract changed for %q", tc.value)
		}
	}
}

func TestRepositoryOIDCRevocationRequest(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := SchemaAt(c, "/components/schemas/OIDCRevocationRequest")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value map[string]any
		valid bool
	}{
		{map[string]any{"token": "unknown", "token_type_hint": "ignored"}, true},
		{map[string]any{"token": ""}, false},
		{map[string]any{"client_id": "public"}, false},
		{map[string]any{"token": "unknown", "client_secret": strings.Repeat("s", 32)}, false},
		{map[string]any{"token": "unknown", "client_id": "post", "client_secret": strings.Repeat("s", 32)}, true},
	} {
		if (schema.Validate(tc.value) == nil) != tc.valid {
			t.Error("revocation field contract changed (values withheld)")
		}
	}
}

func TestRepositoryJWKEncodings(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	integer, err := SchemaAt(c, "/components/schemas/JWKUnsignedInteger")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"AQAB", true}, {"AQ", true}, {"_w", true}, {"__8", true}, {"____", true},
		{"", false}, {"A", false}, {"AA", false}, {"AAEAAQ", false},
		{"AR", false}, {"__9", false}, {"AQAB=", false}, {"AQAB\n", false},
	} {
		if (integer.Validate(tc.value) == nil) != tc.valid {
			t.Errorf("integer encoding disagrees for %q", tc.value)
		}
	}
	for _, family := range []string{"RSA", "P-256", "P-384", "P-521", "Ed25519"} {
		t.Run(family, func(t *testing.T) {
			var signer crypto.Signer
			var err error
			switch family {
			case "RSA":
				signer, err = rsa.GenerateKey(rand.Reader, 2048)
			case "Ed25519":
				_, signer, err = ed25519.GenerateKey(rand.Reader)
			default:
				curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[family]
				signer, err = ecdsa.GenerateKey(curve, rand.Reader)
			}
			if err != nil {
				t.Fatal("key generation failed")
			}
			der, err := x509.MarshalPKCS8PrivateKey(signer)
			if err != nil {
				t.Fatal("key encoding failed")
			}
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := kms.NewCryptoKeyStoreConfig([]string{fmt.Sprintf("crypto key contract sign-verify from file %s", path)})
			if err != nil {
				t.Fatal(err)
			}
			store, err := kms.NewCryptoKeyStore(cfg, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			public, err := store.GetJWKS()
			if err != nil {
				t.Fatal("public export failed")
			}
			private, err := store.GetJWKSPrivateKeys("jwk", "json")
			if err != nil {
				t.Fatal("private export failed")
			}
			var set map[string]any
			if json.Unmarshal(public, &set) != nil {
				t.Fatal("invalid public JSON")
			}
			publicKey := set["keys"].([]any)[0].(map[string]any)
			if json.Unmarshal(private, &set) != nil {
				t.Fatal("invalid private JSON")
			}
			privateKey := set["keys"].([]any)[0].(map[string]any)["private_key"].(map[string]any)
			for _, entry := range []struct {
				name  string
				value map[string]any
			}{{"PublicJWK", publicKey}, {"PrivateJWK", privateKey}} {
				schema, err := SchemaAt(c, "/components/schemas/"+entry.name)
				if err != nil || schema.Validate(entry.value) != nil {
					t.Fatalf("%s selected serializer disagrees (material withheld)", entry.name)
				}
				original := entry.value["alg"]
				entry.value["alg"] = "HS256"
				if schema.Validate(entry.value) == nil {
					t.Fatal("symmetric algorithm accepted for asymmetric key")
				}
				entry.value["alg"] = original
				if family == "RSA" {
					entry.value["x"] = "AQAB"
					if schema.Validate(entry.value) == nil {
						t.Fatal("RSA accepted an EC coordinate")
					}
					delete(entry.value, "x")
				} else {
					x := entry.value["x"].(string)
					entry.value["x"] = x[:len(x)-1]
					if schema.Validate(entry.value) == nil {
						t.Fatal("truncated fixed-width coordinate accepted")
					}
					entry.value["x"] = x
					if family == "P-256" || family == "Ed25519" {
						entry.value["x"] = strings.Repeat("A", 42) + "B"
						if schema.Validate(entry.value) == nil {
							t.Fatal("noncanonical coordinate final bits accepted")
						}
						entry.value["x"] = x
					}
				}
			}
			if family == "Ed25519" {
				seed, err := base64.RawURLEncoding.DecodeString(privateKey["d"].(string))
				if err != nil || len(seed) != ed25519.SeedSize {
					t.Fatal("Ed25519 private export is not a seed")
				}
			}
		})
	}
}
