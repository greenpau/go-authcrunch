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
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	storage "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
	"go.uber.org/zap"
)

type credentials struct {
	Access    string `json:"access_token"`
	Refresh   string `json:"refresh_token"`
	SessionID string `json:"session_id"`
}

// A Go embedding host composes the public parser, SQLite Store, refresh engine,
// local identity transactions, KMS and gatekeeper. No portal loader is implied.
func TestE2ESQLiteLoginRestartRefreshAndAuthorization(t *testing.T) {
	const password = "SyntheticSQLitePassword123!"
	path := filepath.Join(privateDirectory(t), "refresh.db")
	config := storageConfig(t, path)
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	binding := tokenrefresh.Binding{Portal: "fixture", Origin: origin, BasePath: "/auth"}
	db, err := identity.NewDatabase(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: password, Roles: []string{"viewer"}}}); err != nil {
		t.Fatal("provision account")
	}
	signer, pub, publicPath := newFixtureSigner(t)
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	signer.reader = reader
	t.Cleanup(func() {
		select {
		case tx := <-signer.blocked:
			_ = tx.Rollback()
		default:
		}
	})
	var mu sync.RWMutex
	var stores [2]*storage.Store
	var managers [3]*tokenrefresh.Manager
	policy := tokenrefresh.Policy{AccessLifetime: time.Minute, IdleTimeout: 5 * time.Minute, AbsoluteTimeout: 10 * time.Minute}
	open := func() {
		t.Helper()
		for i := range stores {
			var err error
			stores[i], err = storage.New(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			managers[i], err = tokenrefresh.NewManager(stores[i], databaseIdentity{db}, signer, policy, binding)
			if err != nil {
				t.Fatal(err)
			}
		}
		wrong := binding
		wrong.Origin += "/other"
		managers[2], err = tokenrefresh.NewManager(stores[0], databaseIdentity{db}, signer, policy, wrong)
		if err != nil {
			t.Fatal(err)
		}
	}
	closeStores := func() {
		t.Helper()
		for _, store := range stores {
			if err := store.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	open()
	t.Cleanup(closeStores)
	restart := func() {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		// The host drains requests, retains its identity epoch and signing key, and
		// rebuilds all managers. SQLite owns only refresh-family durability.
		closeStores()
		open()
	}
	gate, err := authz.NewGatekeeper(&authz.PolicyConfig{
		Name: "sqlite-consumer", AuthRedirectDisabled: true, ValidateBearerHeader: true, ValidateMethodPath: true,
		RawCryptoKeyStoreConfig: []string{cfgutil.EncodeArgs([]string{"crypto", "key", "public", "verify", "from", "file", publicPath})},
		AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer", "match method GET", "exact match path /private"}, Action: "allow stop"}},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		if r.URL.Path == "/private" {
			ar := requests.NewAuthorizationRequest()
			if gate.Authenticate(w, r, ar) != nil {
				http.Error(w, "invalid", http.StatusUnauthorized)
				return
			}
			if !ar.Response.Authorized {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		index := 0
		switch r.Header.Get("X-Fixture-Client") {
		case "second":
			index = 1
		case "wrong-binding":
			index = 2
		}
		manager := managers[index]
		var input credentials
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		var result *tokenrefresh.Result
		var err error
		switch r.URL.Path {
		case "/auth/login":
			username, pwd, ok := r.BasicAuth()
			request := &requests.Request{User: requests.User{Username: username, Password: pwd}}
			if !ok || db.AuthenticateUser(request) != nil {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			proof := request.Authentication
			principal := tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: proof.UserID, Subject: username, BackendVersion: proof.BackendVersion, CredentialVersion: proof.CredentialVersion, AuthTime: proof.AuthenticatedAt, Methods: []string{proof.Method}, Challenges: []string{"password"}, Audience: []string{"api"}}
			result, err = manager.IssueReplacing(r.Context(), principal, tokenrefresh.BodyTransport, []string{input.Refresh})
		case "/auth/refresh":
			result, err = manager.Refresh(r.Context(), input.Refresh, tokenrefresh.BodyTransport)
		case "/auth/logout":
			err = manager.Logout(r.Context(), input.Refresh, tokenrefresh.BodyTransport)
			if err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, tokenrefresh.ErrInvalid) || errors.Is(err, tokenrefresh.ErrDenied) {
				status = http.StatusUnauthorized
			}
			http.Error(w, "issuance failed", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(credentials{Access: result.AccessToken, Refresh: result.RefreshToken, SessionID: result.SessionID})
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 5 * time.Second
	send := func(route, mode, pwd, token string, want int) credentials {
		t.Helper()
		data, err := json.Marshal(credentials{Refresh: token})
		if err != nil {
			t.Fatal(err)
		}
		method := http.MethodPost
		if route == "/private" {
			method = http.MethodGet
		}
		req, err := http.NewRequestWithContext(t.Context(), method, origin+route, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Fixture-Client", mode)
		if route == "/auth/login" {
			req.SetBasicAuth("alice", pwd)
		}
		if route == "/private" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("consumer request failed", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s (%s): status %d, want %d", route, mode, response.StatusCode, want)
		}
		var result credentials
		if want == 200 {
			if json.Unmarshal(body, &result) != nil || result.Access == "" || result.Refresh == "" || result.SessionID == "" {
				t.Fatal("missing committed credentials")
			}
		} else if bytes.Contains(body, []byte("access_token")) || bytes.Contains(body, []byte("refresh_token")) {
			t.Fatal("failure exposed staged credentials")
		}
		return result
	}
	verify := func(result credentials) jwt.MapClaims {
		t.Helper()
		parsed, err := jwt.Parse(result.Access, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(origin+"/auth"), jwt.WithAudience("api"), jwt.WithExpirationRequired())
		if err != nil || !parsed.Valid {
			t.Fatal("independent JWT verification failed")
		}
		claims := parsed.Claims.(jwt.MapClaims)
		if claims["sub"] != "alice" || claims["sid"] != result.SessionID || claims["amr"].([]any)[0] != "pwd" || claims["roles"].([]any)[0] != "viewer" {
			t.Fatal("identity or authentication evidence changed")
		}
		send("/private", "", "", result.Access, 204)
		return claims
	}
	send("/auth/login", "", "wrong-password", "", 401)
	first := send("/auth/login", "", password, "", 200)
	claims := verify(first)
	// Inspect a live committed family, with every SQLite descriptor closed first.
	// A raw file close while SQLite is active can release its POSIX file locks.
	var data []byte
	var readErr error
	func() {
		mu.Lock()
		defer mu.Unlock()
		closeStores()
		data, readErr = os.ReadFile(path)
		open()
	}()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(data, []byte("alice")) {
		t.Fatal("privacy assertion did not inspect a live identity record")
	}
	for _, credential := range []string{first.Refresh, first.Access} {
		if bytes.Contains(data, []byte(credential)) {
			t.Fatal("database persisted raw bearer credentials")
		}
	}
	send("/auth/login", "second", password, "", 503) // shared capacity of one
	send("/auth/refresh", "wrong-binding", "", first.Refresh, 401)
	signer.fail.Store(true)
	send("/auth/refresh", "second", "", first.Refresh, 503)
	signer.fail.Store(false)
	// Cancel a real TLS request after signing starts. A canceled request must not
	// spend its refresh credential or disable the handle serving other requests.
	signer.waitCancel.Store(true)
	cancelContext, cancelRequest := context.WithCancel(t.Context())
	defer cancelRequest()
	payload, err := json.Marshal(credentials{Refresh: first.Refresh})
	if err != nil {
		t.Fatal(err)
	}
	canceledRequest, err := http.NewRequestWithContext(cancelContext, http.MethodPost, origin+"/auth/refresh", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	canceledRequest.Header.Set("X-Fixture-Client", "second")
	finished := make(chan error, 1)
	go func() {
		response, err := client.Do(canceledRequest)
		if response != nil {
			_ = response.Body.Close()
		}
		finished <- err
	}()
	select {
	case <-signer.signing:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled request did not reach signing")
	}
	cancelRequest()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal("request did not cancel", err)
	}
	select {
	case <-signer.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not observe client cancellation")
	}
	current := send("/auth/refresh", "second", "", first.Refresh, 200)
	verify(current)
	// A real lock timeout before rotation preserves the current credential.
	lock, err := reader.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := lock.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	send("/auth/refresh", "second", "", current.Refresh, 503)
	if _, err := lock.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	restart()
	current = send("/auth/refresh", "second", "", current.Refresh, 200)
	nextClaims := verify(current)
	if current.SessionID != first.SessionID || current.Refresh == first.Refresh || nextClaims["auth_time"] != claims["auth_time"] || nextClaims["jti"] == claims["jti"] {
		t.Fatal("rotation lost grant continuity")
	}
	// Invalid reconfiguration returns no runtime and leaves current handles usable.
	incompatible := *config
	incompatible.MaxSessions++
	if candidate, err := storage.New(t.Context(), &incompatible); err == nil || candidate != nil {
		t.Fatal("incompatible reload accepted")
	}
	// A lookalike SQLite prefix is an ordinary foreign object. Reopening must
	// reject it; SQL LIKE would accidentally treat its underscore as wildcard.
	if _, err := reader.ExecContext(t.Context(), "CREATE TABLE sqliteX_unrelated(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	candidate, reloadErr := storage.New(t.Context(), config)
	if candidate != nil {
		_ = candidate.Close()
	}
	if reloadErr == nil || candidate != nil {
		t.Fatal("foreign schema reload published a runtime")
	}
	current = send("/auth/refresh", "", "", current.Refresh, 200)
	verify(current)
	if _, err := reader.ExecContext(t.Context(), "DROP TABLE sqliteX_unrelated"); err != nil {
		t.Fatal(err)
	}
	restart()
	send("/auth/refresh", "second", "", first.Refresh, 401) // durable oldest-spent replay
	send("/auth/refresh", "", "", current.Refresh, 401)
	if err := managers[0].ValidateSession(t.Context(), current.SessionID, tokenrefresh.BodyTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("replayed family remains live", err)
	}
	// A fresh login replaces even a spent credential atomically at capacity.
	first = send("/auth/login", "", password, "", 200)
	current = send("/auth/refresh", "second", "", first.Refresh, 200)
	replacement := send("/auth/login", "second", password, first.Refresh, 200)
	verify(replacement)
	send("/auth/refresh", "", "", current.Refresh, 401)
	restart()
	current = send("/auth/refresh", "", "", replacement.Refresh, 200)
	send("/auth/logout", "second", "", replacement.Refresh, 204) // logout by spent credential
	restart()
	send("/auth/refresh", "", "", current.Refresh, 401)
	// Failed SQLite COMMIT after signing never releases the staged access/refresh
	// credentials. This specific SQLITE_BUSY case rolls back, but callers cannot
	// generally retry an ErrCommitUncertain; the host requires a fresh login.
	first = send("/auth/login", "", password, "", 200)
	before := signer.calls.Load()
	signer.blockCommit.Store(true)
	send("/auth/refresh", "second", "", first.Refresh, 503)
	if signer.calls.Load() != before+1 {
		t.Fatal("commit failure did not follow signing")
	}
	select {
	case tx := <-signer.blocked:
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("commit reader was not established")
	}
	send("/auth/refresh", "second", "", first.Refresh, 503) // poisoned handle remains closed
	restart()
	first = send("/auth/login", "", password, first.Refresh, 200)
	verify(first)
	account := &requests.Request{User: requests.User{Username: "alice", Password: password}}
	if db.AuthenticateUser(account) != nil || db.RevokeUserSessions(t.Context(), account.Authentication.UserID) != nil {
		t.Fatal("revoke identity")
	}
	send("/auth/refresh", "second", "", first.Refresh, 401)
	restart()
	send("/auth/refresh", "", "", first.Refresh, 401)
}

func TestE2ESQLiteProviderSnapshotRestart(t *testing.T) {
	config := storageConfig(t, filepath.Join(privateDirectory(t), "provider.db"))
	signer, pub, _ := newFixtureSigner(t)
	var mu sync.RWMutex
	var store *storage.Store
	var manager *tokenrefresh.Manager
	binding := tokenrefresh.Binding{Portal: "provider-consumer", Origin: "https://auth.example.test", BasePath: "/auth"}
	open := func() {
		t.Helper()
		var err error
		store, err = storage.New(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		manager, err = tokenrefresh.NewManager(store, capturedProviderIdentity{}, signer, tokenrefresh.Policy{AccessLifetime: time.Minute, IdleTimeout: 2 * time.Minute, AbsoluteTimeout: 4 * time.Minute}, binding)
		if err != nil {
			t.Fatal(err)
		}
	}
	open()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	principal := tokenrefresh.Principal{Source: tokenrefresh.ProviderSnapshotSource, Backend: "upstream", BackendKind: "oauth", Realm: "upstream", UserID: "immutable-provider-sub", Subject: "immutable-provider-sub", AuthTime: time.Now().Unix(), Methods: []string{"federated"}, ProviderSnapshot: []byte(`{"sub":"immutable-provider-sub","roles":["viewer"],"provider_name":"Captured User"}`)}
	first, err := manager.Issue(t.Context(), principal, tokenrefresh.BodyTransport)
	if err != nil {
		t.Fatal(err)
	}
	principal.ProviderSnapshot[0] = 'x'
	first.Principal.ProviderSnapshot[0] = 'y'
	restart := func() {
		mu.Lock()
		defer mu.Unlock()
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		open()
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		if r.Method != http.MethodPost || r.URL.Path != "/auth/refresh" {
			http.NotFound(w, r)
			return
		}
		var input credentials
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		result, err := manager.Refresh(r.Context(), input.Refresh, tokenrefresh.BodyTransport)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, tokenrefresh.ErrInvalid) || errors.Is(err, tokenrefresh.ErrDenied) {
				status = http.StatusUnauthorized
			}
			http.Error(w, "refresh failed", status)
			return
		}
		_ = json.NewEncoder(w).Encode(credentials{Access: result.AccessToken, Refresh: result.RefreshToken, SessionID: result.SessionID})
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	refresh := func(token string, want int) credentials {
		t.Helper()
		body, err := json.Marshal(credentials{Refresh: token})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Post(server.URL+"/auth/refresh", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatal("provider storage refresh status", resp.StatusCode)
		}
		var output credentials
		if want == http.StatusOK && json.NewDecoder(resp.Body).Decode(&output) != nil {
			t.Fatal("invalid credential response")
		}
		return output
	}
	restart()
	signer.fail.Store(true)
	refresh(first.RefreshToken, http.StatusServiceUnavailable)
	signer.fail.Store(false)
	next := refresh(first.RefreshToken, http.StatusOK)
	parsed, err := jwt.Parse(next.Access, func(token *jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"EdDSA", "Ed25519"}))
	if err != nil || !parsed.Valid {
		t.Fatal("renewed provider signature invalid")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != principal.Subject || claims["sid"] != first.SessionID || claims["auth_time"].(float64) != float64(principal.AuthTime) || claims["provider_name"] != "Captured User" || claims["amr"].([]any)[0] != "federated" {
		t.Fatal("provider evidence lost at reopen")
	}
	restart()
	refresh(first.RefreshToken, http.StatusUnauthorized)
	refresh(next.Refresh, http.StatusUnauthorized)
}
