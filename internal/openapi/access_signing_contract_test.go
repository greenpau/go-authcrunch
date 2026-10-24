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

package openapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
)

func TestRepositorySelectedAccessJWKS(t *testing.T) {
	compiler, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := SchemaAt(compiler, "/components/schemas/PublicJWK")
	if err != nil {
		t.Fatal(err)
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate contract key")
	}
	path := filepath.Join(t.TempDir(), "access.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}), 0600); err != nil {
		t.Fatal("write contract key")
	}
	for _, kid := range []string{"current", "0"} {
		t.Run(kid, func(t *testing.T) {
			signer, err := rsapss.New(&rsapss.Config{KeyFile: path, KeyID: kid, Issuer: "https://auth.example.test/auth", Audience: "api"})
			if err != nil {
				t.Fatal("create contract signer")
			}
			data, err := signer.PublicJWKS()
			if err != nil {
				t.Fatal("export contract public key")
			}
			var set struct {
				Keys []map[string]any `json:"keys"`
			}
			if json.Unmarshal(data, &set) != nil || len(set.Keys) != 1 {
				t.Fatal("invalid public key document")
			}
			key := set.Keys[0]
			if key["alg"] != "PS256" || key["kid"] != kid || schema.Validate(key) != nil {
				t.Fatal("real selected public key disagrees with authored schema")
			}
			for name, change := range map[string]func(map[string]any){
				"missing selected ID": func(k map[string]any) { delete(k, "kid") },
				"private material":    func(k map[string]any) { k["d"] = "AQAB" },
				"other PSS algorithm": func(k map[string]any) { k["alg"] = "PS384" },
				"short modulus":       func(k map[string]any) { k["n"] = "AQAB" },
			} {
				t.Run(name, func(t *testing.T) {
					candidate := maps.Clone(key)
					change(candidate)
					if schema.Validate(candidate) == nil {
						t.Fatal("invalid selected key shape was accepted")
					}
				})
			}
			legacy := maps.Clone(key)
			legacy["alg"] = "RS512"
			delete(legacy, "kid")
			if schema.Validate(legacy) != nil {
				t.Fatal("selected schema restriction changed ordinary default-key discovery")
			}
		})
	}
}
