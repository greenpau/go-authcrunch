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

package authcrunch_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authcrunch "github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	accountparser "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite/parser"
	"go.uber.org/zap"
)

const externalIdentityKey = "synthetic-root-sqlite-identity-signing-secret-0123456789"
const externalIdentityPassword = "Synthetic-root-identity-password-2026!"

func TestE2EServerExternalSQLiteIdentityStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backendConfig, err := accountparser.NewSQLiteIdentityStoreConfigFromDirectives([]string{"name accounts", "realm staff", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "accounts.db")}), "timeout 5s"})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := ids.NewExternalIdentityStoreConfig(backendConfig.Name, "sqlite", backendConfig.Realm, backendConfig)
	if err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), backendConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.Create(t.Context(), &accounts.Account{Username: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}}, externalIdentityPassword); err != nil {
		t.Fatal(err)
	}
	var runtime *authcrunch.Server
	var rootMu sync.RWMutex
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootMu.RLock()
		defer rootMu.RUnlock()
		portal, err := runtime.GetPortalByName("portal")
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("external identity portal request failed", err)
		}
	}))
	server.StartTLS()
	defer func() {
		server.Close()
		if runtime != nil {
			_ = runtime.Close()
		}
	}()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	config := &authcrunch.Config{
		State:                  &state.Config{Directory: filepath.Join(dir, "state")},
		ExternalIdentityStores: []*ids.ExternalIdentityStoreConfig{descriptor},
		AuthenticationPortals:  []*authn.PortalConfig{{Name: "portal", RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + externalIdentityKey}, RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"staff"}, PublicOrigin: server.URL, BasePath: "/auth", BodyTransportEnabled: true}}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	restoredConfig := func() *authcrunch.Config {
		t.Helper()
		var restored authcrunch.Config
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		return &restored
	}
	// Validation and missing bindings must not create state or close borrowed stores.
	if err := restoredConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	if root, err := authcrunch.NewServer(restoredConfig(), zap.NewNop()); err == nil || root != nil {
		t.Fatal("missing external binding accepted")
	}
	if _, err := os.Stat(config.State.Directory); !os.IsNotExist(err) {
		t.Fatal("missing binding acquired persistent state")
	}
	newRoot := func() *authcrunch.Server {
		t.Helper()
		root, err := authcrunch.NewServerWithOptions(restoredConfig(), zap.NewNop(), authcrunch.ServerOptions{IdentityStores: map[string]ids.IdentityStore{"accounts": store}})
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	runtime = newRoot()
	verify := func(raw string) jwt.MapClaims {
		t.Helper()
		token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(externalIdentityKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
		if err != nil || !token.Valid {
			t.Fatal("invalid root-issued credential", err)
		}
		claims := token.Claims.(jwt.MapClaims)
		if claims["sub"] != "alice" || claims["origin"] != "staff" {
			t.Fatal("root-issued credential has wrong identity")
		}
		return claims
	}
	login := func(password string) *authclient.Credentials {
		t.Helper()
		native, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL + "/auth", Realm: "staff", Username: "alice", Password: password, RefreshTransport: authclient.RefreshTransportBody}, authclient.Options{HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		result, err := native.Authenticate(t.Context())
		if err != nil {
			t.Fatal("native root login failed", err)
		}
		verify(result.AccessToken)
		return result
	}
	refresh := func(token string, want int) string {
		t.Helper()
		data, _ := json.Marshal(map[string]string{"refresh_token": token})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth/api/refresh_token", strings.NewReader(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("root refresh status=%d want=%d", resp.StatusCode, want)
		}
		if want != 200 {
			return ""
		}
		var result struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
			t.Fatal(err)
		}
		verify(result.AccessToken)
		return result.RefreshToken
	}
	native := login(externalIdentityPassword)
	current := refresh(native.RefreshToken, 200)
	if _, err := store.OverwriteUserRoles("alice", "alice@example.test", []string{"authp/reader"}); err != nil {
		t.Fatal(err)
	}
	refresh(current, 401)
	changed := login(externalIdentityPassword)
	roles := verify(changed.AccessToken)["roles"].([]any)
	if len(roles) != 1 || roles[0] != "authp/reader" {
		t.Fatal("root issued stale roles")
	}
	// Reconstructing a root around the same backend preserves valid evidence;
	// changing its normalized configuration digest retires persisted sessions.
	rootMu.Lock()
	func() {
		defer rootMu.Unlock()
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		runtime = newRoot()
	}()
	next := refresh(changed.RefreshToken, 200)
	adjusted := *backendConfig
	adjusted.Timeout = "4s"
	updatedDescriptor, err := ids.NewExternalIdentityStoreConfig(adjusted.Name, "sqlite", adjusted.Realm, &adjusted)
	if err != nil {
		t.Fatal(err)
	}
	config.ExternalIdentityStores[0] = updatedDescriptor
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	rootMu.Lock()
	func() {
		defer rootMu.Unlock()
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		runtime = newRoot()
	}()
	refresh(next, 401)
	changed = login(externalIdentityPassword)
	// Recreate both root and backend, retaining account and session files. Backend
	// proof epochs must invalidate old refresh credentials even after restoration.
	rootMu.Lock()
	func() {
		defer rootMu.Unlock()
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		if !store.Configured() {
			t.Fatal("root closed borrowed identity store")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = accounts.New(t.Context(), backendConfig)
		if err != nil {
			t.Fatal(err)
		}
		runtime = newRoot()
	}()
	refresh(changed.RefreshToken, 401)
	verify(changed.AccessToken) // Signed JWTs retain their bounded lifetime.
	afterRestart := login(externalIdentityPassword)
	refresh(afterRestart.RefreshToken, 200)
	if err := store.DisableUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/auth/basic/login/staff", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("alice", externalIdentityPassword)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 || response.Header.Get("Authorization") != "" {
		t.Fatal("disabled identity obtained authority")
	}
}

func TestE2EServerExternalIdentityStoreOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := accountparser.NewSQLiteIdentityStoreConfigFromDirectives([]string{"name accounts", "realm staff", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "accounts.db")})})
	if err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	descriptor, err := ids.NewExternalIdentityStoreConfig(cfg.Name, "sqlite", cfg.Realm, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rootConfig := func() *authcrunch.Config {
		return &authcrunch.Config{ExternalIdentityStores: []*ids.ExternalIdentityStoreConfig{descriptor}, AuthenticationPortals: []*authn.PortalConfig{{Name: "first"}, {Name: "second"}}}
	}
	options := authcrunch.ServerOptions{IdentityStores: map[string]ids.IdentityStore{"accounts": store}}
	config := rootConfig()
	config.AuthenticationPortals[1].Name = "first"
	if root, err := authcrunch.NewServerWithOptions(config, zap.NewNop(), options); err == nil || root != nil {
		t.Fatal("duplicate portal accepted")
	}
	if !store.Configured() {
		t.Fatal("partial constructor closed borrowed store")
	}
	root, err := authcrunch.NewServerWithOptions(rootConfig(), zap.NewNop(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if !store.Configured() {
		t.Fatal("shared store closed with root")
	}
	// OIDC's local identity adapter remains deliberately unavailable for SQLite.
	config = rootConfig()
	config.AuthenticationPortals = config.AuthenticationPortals[:1]
	config.AuthenticationPortals[0].OIDCProvider = &oidc.Config{Enabled: true, Issuer: "https://auth.example.test/auth", Realms: []string{"staff"}, SigningKeyFiles: []string{"testdata/rskeys/test_2_pri.pem"}, Clients: []*oidc.ClientConfig{{ClientID: "native", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://client.example.test/callback"}}}}
	if root, err := authcrunch.NewServerWithOptions(config, zap.NewNop(), options); err == nil || root != nil || !strings.Contains(err.Error(), "local identity store") {
		t.Fatal("SQLite OIDC restriction not enforced", err)
	}
	if !store.Configured() {
		t.Fatal("rejected OIDC consumer closed borrowed store")
	}
}
