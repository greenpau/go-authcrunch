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

// Package accesssigner provides real RSA fixtures only for repository tests.
package accesssigner

import (
	"context"
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

	"github.com/greenpau/go-authcrunch/pkg/kms"
	profileparser "github.com/greenpau/go-authcrunch/pkg/kms/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
	"go.uber.org/zap"
)

// Fixture owns temporary PEM input and a real independent signer.
type Fixture struct {
	Key                     *rsa.PrivateKey                 `json:"-" xml:"-" yaml:"-"`
	Signer                  *rsapss.Signer                  `json:"-" xml:"-" yaml:"-"`
	Config                  *rsapss.Config                  `json:"-" xml:"-" yaml:"-"`
	Descriptor              *kms.ExternalAccessSignerConfig `json:"-" xml:"-" yaml:"-"`
	Profile                 *kms.AccessTokenProfileConfig   `json:"-" xml:"-" yaml:"-"`
	PrivateFile, PublicFile string                          `json:"-" xml:"-" yaml:"-"`
}

// New creates private temporary keys, a PS256 signer and its matching profile.
func New(t testing.TB, issuer string) *Fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privateFile, publicFile := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, block := range map[string]*pem.Block{privateFile: {Type: "PRIVATE KEY", Bytes: private}, publicFile: {Type: "PUBLIC KEY", Bytes: public}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &rsapss.Config{KeyFile: privateFile, KeyID: "current", Algorithm: "PS256", Issuer: issuer, Audience: "api", MaxLifetime: "5m"}
	signer, err := rsapss.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := signer.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := &kms.ExternalAccessSignerConfig{Name: "access", Kind: metadata.Kind, ConfigDigest: metadata.ConfigDigest, Policy: metadata.Policy}
	profile, err := profileparser.NewAccessTokenProfileConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"issuer", issuer}), "audience api", "key ids current", "max lifetime 300"})
	if err != nil {
		t.Fatal(err)
	}
	return &Fixture{Key: key, Signer: signer, Config: cfg, Descriptor: descriptor, Profile: profile, PrivateFile: privateFile, PublicFile: publicFile}
}
// CryptoConfig returns a detached profile with explicit public verification input.
func (f *Fixture) CryptoConfig() *kms.CryptoKeyStoreConfig {
	return &kms.CryptoKeyStoreConfig{AccessTokenProfile: f.Profile.Clone(), RawKeyConfigs: []string{"crypto key current verify from file " + f.PublicFile}}
}
// Store constructs a strict verifier from the fixture's public key.
func (f *Fixture) Store(t testing.TB) *kms.CryptoKeyStore {
	t.Helper()
	store, err := kms.NewCryptoKeyStore(f.CryptoConfig(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return store
}
// Claims returns a fresh, short-lived grant matching the fixture's profile.
func (f *Fixture) Claims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": f.Profile.Issuer, "aud": "api", "sub": "alice", "roles": []string{"authp/user"}, "iat": now, "nbf": now, "exp": now + 60}
}
// Token signs claims through the real selected signer.
func (f *Fixture) Token(t testing.TB, claims map[string]any) string {
	t.Helper()
	token, err := f.Signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// RawToken deliberately bypasses issuer validation for independent negative controls.
func (f *Fixture) RawToken(t testing.TB, header, payload []byte, salt int, rsaPKCS1 bool) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	var err error
	if rsaPKCS1 {
		signature, err = rsa.SignPKCS1v15(rand.Reader, f.Key, crypto.SHA256, digest[:])
	} else {
		signature, err = rsa.SignPSS(rand.Reader, f.Key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: salt})
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
// JSON serializes a fixture value or fails its owning test.
func JSON(t testing.TB, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
