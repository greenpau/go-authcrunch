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

package authn

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	refreshsqlite "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
	"go.uber.org/zap"
)

// The standalone caller persists its own changing whole-configuration epoch,
// including periods with no portal. Keeping the same already configured identity
// handle isolates this caller-epoch contract; the root tests separately reopen
// the identity database and restore its durable identity epoch.
func TestE2EManagedRefreshStandaloneCallerEpoch(t *testing.T) {
	identityFixture := newRefreshPortal(t, true, false)
	identityFixture.portal.Close()
	var mu sync.RWMutex
	var portal *Portal
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		if portal == nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := portal.ServeHTTPAt(r.Context(), w, r, requests.NewRequest(), "/auth"); err != nil {
			t.Error("standalone portal request failed")
		}
	}))
	origin := "https://" + server.Listener.Addr().String()
	server.StartTLS()
	defer server.Close()
	server.Client().Timeout = 10 * time.Second
	directory := filepath.Join(t.TempDir(), "refresh")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	databaseConfig := refreshsqlite.Config{Path: filepath.Join(directory, "refresh.db"), MaxSessions: 1, MaxRotations: 16}
	if err := databaseConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	descriptor, err := tokenrefresh.NewExternalStoreConfig("durable", "sqlite", 1, 16, databaseConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PortalConfig{Name: "standalone", IdentityStores: []string{"localdb"}, RawCryptoKeyStoreConfig: []string{"crypto key standalone sign-verify " + refreshTestSecret}, RefreshTokens: &TokenRefreshConfig{Enabled: true, Store: "durable", Realms: []string{"local"}, PublicOrigin: origin, BasePath: "/auth", BodyTransportEnabled: true, MaxSessions: 1, MaxRotations: 16}}
	configSnapshot, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stateConfig := &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
	var storage *state.Store
	var database *refreshsqlite.Store
	stop := func() {
		mu.Lock()
		defer mu.Unlock()
		if portal != nil {
			portal.Close()
			portal = nil
		}
		if storage != nil {
			if err := storage.Close(); err != nil {
				t.Error("caller state close failed")
			}
			storage = nil
		}
		if database != nil {
			if err := database.Close(); err != nil {
				t.Error("caller SQLite close failed")
			}
			database = nil
		}
	}
	defer stop()
	// This is caller-owned application bookkeeping, not an API that assumes a
	// reusable digest can observe transitions while the selected portal is absent.
	openEpoch := func(present bool) string {
		t.Helper()
		var err error
		storage, err = state.Open(stateConfig)
		if err != nil {
			t.Fatal(err)
		}
		var configuration json.RawMessage
		if present {
			configuration = append([]byte(nil), configSnapshot...)
		}
		binding, err := state.Binding(struct {
			Portal       json.RawMessage
			RefreshStore *tokenrefresh.ExternalStoreConfig
		}{configuration, func() *tokenrefresh.ExternalStoreConfig {
			if present {
				return descriptor
			}
			return nil
		}()})
		if err != nil {
			t.Fatal(err)
		}
		record, err := storage.OpenRecord("caller-whole-configuration", binding)
		if err != nil {
			t.Fatal(err)
		}
		epoch, err := record.Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(epoch) == 0 {
			epoch = make([]byte, 32)
			if _, err := rand.Read(epoch); err != nil {
				t.Fatal(err)
			}
			if err := record.Save(epoch); err != nil {
				t.Fatal(err)
			}
		}
		if len(epoch) != 32 {
			t.Fatal("invalid caller epoch")
		}
		return hex.EncodeToString(epoch)
	}
	start := func() string {
		t.Helper()
		epoch := openEpoch(true)
		var err error
		database, err = refreshsqlite.New(t.Context(), &databaseConfig)
		if err != nil {
			t.Fatal(err)
		}
		var config PortalConfig
		if json.Unmarshal(configSnapshot, &config) != nil {
			t.Fatal("standalone config snapshot failed")
		}
		candidate, err := NewPortal(PortalParameters{Config: &config, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{identityFixture.store}, RefreshStore: &tokenrefresh.ExternalStoreBinding{Config: descriptor, Store: database}})
		if err != nil {
			t.Fatal(err)
		}
		if err := candidate.ConfigurePersistentState(storage, epoch); err != nil {
			candidate.Close()
			t.Fatal(err)
		}
		mu.Lock()
		portal = candidate
		mu.Unlock()
		return epoch
	}
	post := func(path string, body any, want int) apiauth.AuthResponse {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal("standalone TLS request failed")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		if err != nil || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("standalone TLS response failed: status %d want %d", response.StatusCode, want)
		}
		var result apiauth.AuthResponse
		if json.Unmarshal(data, &result) != nil {
			t.Fatal("standalone response was not JSON")
		}
		if want != http.StatusOK && (result.AccessToken != "" || result.RefreshToken != "" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Authorization") != "") {
			t.Fatal("failed refresh returned a credential")
		}
		return result
	}
	login := func() apiauth.AuthResponse {
		t.Helper()
		first := post("/login", apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", RefreshTransport: "body"}, http.StatusOK)
		if first.SandboxID == "" || first.SandboxSecret == "" {
			t.Fatal("standalone checkpoint missing")
		}
		result := post("/login", apiauth.AuthRequest{Username: tests.TestUser1, Realm: "local", RefreshTransport: "body", SandboxID: first.SandboxID, SandboxSecret: first.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1}, http.StatusOK)
		if !result.Authenticated || result.AccessToken == "" || result.RefreshToken == "" {
			t.Fatal("standalone password login failed")
		}
		return result
	}
	firstEpoch := start()
	first := login()
	firstClaims := tokenClaims(t, first.AccessToken)
	stop()
	if same := start(); same != firstEpoch {
		t.Fatal("same caller configuration replaced its epoch")
	}
	next := post("/api/refresh_token", map[string]string{"refresh_token": first.RefreshToken}, http.StatusOK)
	nextClaims := tokenClaims(t, next.AccessToken)
	if next.SessionID != first.SessionID || nextClaims["auth_time"] != firstClaims["auth_time"] || nextClaims["sub"] != firstClaims["sub"] {
		t.Fatal("standalone compatible restart lost family or authentication evidence")
	}
	stop()
	// No selected portal or SQLite handle exists during this intermediate state.
	if removed := openEpoch(false); removed == firstEpoch {
		t.Fatal("caller failed to record portal removal")
	}
	stop()
	if restored := start(); restored == firstEpoch {
		t.Fatal("caller reused a deterministic epoch after removal")
	}
	post("/api/refresh_token", map[string]string{"refresh_token": next.RefreshToken}, http.StatusUnauthorized)
	fresh := login() // capacity one proves generation retirement releases old rows
	if fresh.SessionID == first.SessionID {
		t.Fatal("new authentication reused removed family")
	}
	post("/api/refresh_token", map[string]string{"refresh_token": fresh.RefreshToken}, http.StatusOK)
}
