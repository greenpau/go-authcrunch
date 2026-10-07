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

package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	secretssqlite "github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite/parser"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Public parser -> durable lookup -> private gatekeeper configuration -> TLS
// authorization. This file also runs from an isolated external Go module.
func TestE2ESQLiteSecretsGatekeeper(t *testing.T) {
	const first = "synthetic-sqlite-secrets-signing-key-first-0123456789"
	const second = "synthetic-sqlite-secrets-signing-key-second-0123456789"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := parser.NewSQLiteSecretsConfigFromDirectives([]string{"name signing", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "secrets.db")}), "record gateway", "timeout 500ms"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored secretssqlite.Config
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	writer, err := secretssqlite.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Put(t.Context(), map[string]any{"signing_key": first}); err != nil {
		t.Fatal(err)
	}
	reader, err := secretssqlite.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	build := func(ctx context.Context) (*authz.Gatekeeper, error) {
		secret, err := reader.GetString(ctx, "signing_key")
		if err != nil {
			return nil, err
		}
		return authz.NewGatekeeper(&authz.PolicyConfig{Name: "sqlite-secret", AuthRedirectDisabled: true, ValidateBearerHeader: true, RawCryptoKeyStoreConfig: []string{cfgutil.EncodeArgs([]string{"crypto", "key", "verify", secret})}, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}}, zap.NewNop())
	}
	gate, err := build(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.RWMutex
	defer func() { gate.Close() }()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		ar := requests.NewAuthorizationRequest()
		if gate.Authenticate(w, r, ar) != nil || !ar.Response.Authorized {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	check := func(secret string, want int) {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "alice", "email": "alice@example.test", "roles": []string{"viewer"}, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "jti": secret[len(secret)-8:]}).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("status %d, want %d", response.StatusCode, want)
		}
	}
	check(first, http.StatusNoContent)
	if err := writer.Put(t.Context(), map[string]any{"signing_key": second}); err != nil {
		t.Fatal(err)
	}
	// Reload is explicit: current consumers retain the previously validated key.
	check(first, http.StatusNoContent)
	candidate, err := build(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gate.Close()
	gate = candidate
	mu.Unlock()
	check(second, http.StatusNoContent)
	check(first, http.StatusUnauthorized)
	if err := writer.Put(t.Context(), map[string]any{"signing_key": 42}); err != nil {
		t.Fatal(err)
	}
	if candidate, err := build(t.Context()); candidate != nil || !errors.Is(err, secretssqlite.ErrInvalid) {
		t.Fatal("invalid secret configured a gatekeeper")
	}
	check(second, http.StatusNoContent)
	if err := writer.Delete(t.Context()); err != nil {
		t.Fatal(err)
	}
	if candidate, err := build(t.Context()); candidate != nil || !errors.Is(err, secretssqlite.ErrNotFound) {
		t.Fatal("missing secret configured a gatekeeper")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if candidate, err := build(t.Context()); candidate != nil || !errors.Is(err, secretssqlite.ErrUnavailable) {
		t.Fatal("unavailable secrets used a fallback")
	}
}
