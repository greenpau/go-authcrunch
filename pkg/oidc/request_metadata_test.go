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

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestMetadataSnapshot(t *testing.T) {
	if _, ok := RequestMetadataFromContext(t.Context()); ok {
		t.Fatal("unrelated context supplied request metadata")
	}
	r := httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/oidc/token?secret=hidden", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Real-IP", "198.51.100.20")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	snapshot := withRequestMetadata(ctx, r)
	r.URL.Path = "/changed"
	r.Header.Set("X-Real-IP", "203.0.113.30")
	want := RequestMetadata{URL: "https://auth.example.test/auth/oidc/token", SourceAddress: "198.51.100.20"}
	metadata, ok := RequestMetadataFromContext(snapshot)
	if !ok || metadata != want {
		t.Fatalf("request snapshot = %+v, want %+v", metadata, want)
	}
	metadata.URL = "changed"
	if got, _ := RequestMetadataFromContext(snapshot); got != want {
		t.Fatal("metadata shares mutable state")
	}
	encoded, err := json.Marshal(want)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("runtime request metadata was serialized", err)
	}
	cancel()
	if snapshot.Err() != context.Canceled {
		t.Fatal("metadata discarded cancellation")
	}
	callback := httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/callback?code=hidden", nil)
	if got, _ := RequestMetadataFromContext(withRequestMetadata(t.Context(), callback)); got.URL != "https://auth.example.test/auth/callback" {
		t.Fatal("metadata rewrote the current endpoint path")
	}
}

type metadataVerifier struct {
	IdentityVerifier
	seen []RequestMetadata
}

func (v *metadataVerifier) WithIdentity(ctx context.Context, proof Authentication, apply func(Identity) error) error {
	metadata, ok := RequestMetadataFromContext(ctx)
	if !ok {
		return ErrIdentityDenied
	}
	v.seen = append(v.seen, metadata)
	return v.IdentityVerifier.WithIdentity(ctx, proof, apply)
}

func TestRequestMetadataPublicEntryPoints(t *testing.T) {
	f := newProviderFixture(t)
	verifier := &metadataVerifier{IdentityVerifier: f.verifier}
	f.provider.verifier = verifier
	session := responseCookie(t, f.login(t), f.provider.sessionCookie)
	code := oidcUnitCode(t, oidcUnitAuthorize(t, f, session))
	if response := oidcUnitToken(t, f, code); response.Code != http.StatusOK {
		t.Fatal("request-aware verifier blocked token exchange")
	}
	wantPaths := []string{"/auth/login", "/auth/oidc/authorize", "/auth/oidc/token"}
	for _, path := range wantPaths {
		found := false
		for _, metadata := range verifier.seen {
			if metadata.URL == oidcTestOrigin+path && metadata.SourceAddress == "192.0.2.1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing current request metadata for %s", path)
		}
	}
}
