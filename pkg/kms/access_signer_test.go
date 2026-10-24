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
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"go.uber.org/zap"
)

type signerProbe struct {
	kms.AccessSigner
	metadata                                          *kms.AccessSignerMetadata
	public                                            []byte
	panicMetadata, panicPublic                        bool
	metadataCalls, publicCalls, signCalls, closeCalls int
}

func (p *signerProbe) Metadata() (kms.AccessSignerMetadata, error) {
	p.metadataCalls++
	if p.panicMetadata {
		panic("private metadata canary")
	}
	if p.metadata != nil {
		return *p.metadata, nil
	}
	return p.AccessSigner.Metadata()
}
func (p *signerProbe) PublicJWKS() ([]byte, error) {
	p.publicCalls++
	if p.panicPublic {
		panic("private discovery canary")
	}
	if p.public != nil {
		return p.public, nil
	}
	return p.AccessSigner.PublicJWKS()
}
func (p *signerProbe) Sign(ctx context.Context, c map[string]any) (string, error) {
	p.signCalls++
	return p.AccessSigner.Sign(ctx, c)
}
func (p *signerProbe) Close() error { p.closeCalls++; return nil }
func TestAccessSignerPreparedOwnership(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	probe := &signerProbe{AccessSigner: f.Signer}
	input := &kms.AccessSignerBinding{Config: f.Descriptor, Signer: probe}
	prepared, err := input.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	replacement := &signerProbe{AccessSigner: f.Signer}
	prepared.Signer = replacement
	prepared.Config.Name = "changed"
	input.Config.Policy.Audience = "changed"
	second, err := prepared.Prepare()
	if err != nil || second.Config.Name != "access" || second.Config.Policy.Audience != "api" {
		t.Fatal("prepared descriptor was mutable")
	}
	if _, err := second.Sign(t.Context(), f.Claims()); err != nil || probe.signCalls != 1 || replacement.signCalls != 0 {
		t.Fatal("prepared runtime was replaced")
	}
	if probe.metadataCalls != 1 || probe.publicCalls != 1 || probe.closeCalls != 0 {
		t.Fatal("borrowed accessor capture or ownership changed")
	}
	if err := f.Store(t).MatchAccessSigner(second); err != nil {
		t.Fatal(err)
	}
	// The caller may replace PEM files; discovery/matching use their captured keys.
	public, err := second.Signer.PublicJWKS()
	if err != nil || len(public) == 0 {
		t.Fatal("borrowed signer unusable")
	}
}
func TestAccessSignerBindingRejectsUnusedMalformedMetadata(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	good, err := f.Signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(good, &document) != nil {
		t.Fatal("fixture discovery decode failed")
	}
	for name, change := range map[string]func(map[string]any){"weak modulus": func(k map[string]any) { k["n"] = base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()) }, "even modulus": func(k map[string]any) {
		k["n"] = base64.RawURLEncoding.EncodeToString(new(big.Int).Lsh(big.NewInt(1), 2047).Bytes())
	}, "short exponent": func(k map[string]any) { k["e"] = "AQ" }, "even exponent": func(k map[string]any) { k["e"] = "BA" }, "huge exponent": func(k map[string]any) { k["e"] = "AQAAAAAB" }, "private member": func(k map[string]any) { k["d"] = "AQAB" }, "wrong kid": func(k map[string]any) { k["kid"] = "other" }} {
		t.Run(name, func(t *testing.T) {
			var d map[string]any
			_ = json.Unmarshal(good, &d)
			change(d["keys"].([]any)[0].(map[string]any))
			p := &signerProbe{AccessSigner: f.Signer, public: fixture.JSON(t, d)}
			if _, err := (&kms.AccessSignerBinding{Config: f.Descriptor, Signer: p}).Prepare(); err == nil {
				t.Fatal("invalid unused signer accepted")
			}
			if p.closeCalls != 0 || p.signCalls != 0 {
				t.Fatal("validation acquired runtime ownership")
			}
		})
	}
	for _, p := range []*signerProbe{{AccessSigner: f.Signer, panicMetadata: true}, {AccessSigner: f.Signer, panicPublic: true}, nil} {
		_, err := (&kms.AccessSignerBinding{Config: f.Descriptor, Signer: p}).Prepare()
		if err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatal("nil or panicking metadata was accepted or leaked")
		}
	}
	metadata, _ := f.Signer.Metadata()
	metadata.Policy.Audience = "different"
	if _, err := (&kms.AccessSignerBinding{Config: f.Descriptor, Signer: &signerProbe{AccessSigner: f.Signer, metadata: &metadata}}).Prepare(); err == nil {
		t.Fatal("metadata mismatch accepted")
	}
}
func TestAccessSignerSelectedRejectsPrivateVerifier(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	cfg := f.CryptoConfig()
	cfg.RawKeyConfigs = []string{"crypto key current verify from file " + f.PrivateFile}
	store, err := kms.NewCryptoKeyStore(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := (&kms.AccessSignerBinding{Config: f.Descriptor, Signer: f.Signer}).Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if store.MatchAccessSigner(binding) == nil {
		t.Fatal("selected portal could expose a private verifier key")
	}
	cfg = f.CryptoConfig()
	store, err = kms.NewCryptoKeyStore(cfg, zap.NewNop())
	if err != nil || store.MatchAccessSigner(binding) != nil {
		t.Fatal("public verifier control failed")
	}
}
func TestAccessSignerDescriptorDigestIdentity(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	policy := f.Descriptor.Policy
	a, err := kms.NewExternalAccessSignerConfig("a", "test", policy, map[string]any{"key": "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := kms.NewExternalAccessSignerConfig("b", "test", policy, map[string]any{"key": "snapshot"})
	if err != nil || a.ConfigDigest != b.ConfigDigest {
		t.Fatal("name contaminated backend digest")
	}
	b.ConfigDigest = strings.ToUpper(b.ConfigDigest)
	if b.Validate() == nil {
		t.Fatal("noncanonical digest accepted")
	}
	if _, err := (&kms.AccessSignerBinding{}).Sign(context.Background(), nil); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("unprepared signer accepted")
	}
}
