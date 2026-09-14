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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type serverLifecycleFixture struct {
	server     *httptest.Server
	mu         sync.RWMutex
	active     *authcrunch.Server
	serialized []byte
}

func newServerLifecycleFixture(t *testing.T) *serverLifecycleFixture {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal("provision lifecycle identity")
	}
	key := []string{"crypto key lifecycle sign-verify from file testdata/rskeys/test_2_pri.pem"}
	cfg := &authcrunch.Config{
		IdentityStores:        []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}},
		AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: key}},
		AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", RawCryptoKeyStoreConfig: key, AuthRedirectDisabled: true, ValidateBearerHeader: true, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}},
		UserRegistration:      &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "registry", Dropbox: filepath.Join(dir, "registrations.json"), EmailProviderName: "unused", AdminEmails: []string{"admin@example.test"}, IdentityStoreName: "local", RealmName: "local"}}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("serialize lifecycle configuration")
	}
	f := &serverLifecycleFixture{serialized: data}
	f.active, err = authcrunch.NewServer(f.config(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		defer f.mu.RUnlock()
		if r.URL.Path == "/protected" {
			gate, err := f.active.GetGatekeeperByName("policy")
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			ar := requests.NewAuthorizationRequest()
			if err := gate.Authenticate(w, r, ar); err != nil {
				t.Error("gatekeeper request failed")
				return
			}
			if ar.Response.Authorized {
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		portal, err := f.active.GetPortalByName("portal")
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("portal request failed")
		}
	}))
	f.server.Client().Timeout = 10 * time.Second
	t.Cleanup(func() {
		f.server.Close()
		if err := f.active.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *serverLifecycleFixture) config(t *testing.T) *authcrunch.Config {
	t.Helper()
	var cfg authcrunch.Config
	if err := json.Unmarshal(f.serialized, &cfg); err != nil {
		t.Fatal("restore lifecycle configuration")
	}
	return &cfg
}

func (f *serverLifecycleFixture) login(t *testing.T) string {
	t.Helper()
	client, err := authclient.NewClient(&authclient.Config{BaseURL: f.server.URL + "/auth", Realm: "local", Username: "alice", Password: tests.TestPwd1}, authclient.Options{HTTPClient: f.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil {
		t.Fatal("lifecycle login failed", err)
	}
	f.authorize(t, credentials.AccessToken)
	return credentials.AccessToken
}

func (f *serverLifecycleFixture) authorize(t *testing.T, token string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal("protected request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("protected response=%d", resp.StatusCode)
	}
}

func TestE2EServerLifecycleReplacement(t *testing.T) {
	f := newServerLifecycleFixture(t)
	token := f.login(t)
	old := f.active
	oldPortal, _ := old.GetPortalByName("portal")
	oldGate, _ := old.GetGatekeeperByName("policy")
	broken := f.config(t)
	// A late gatekeeper error occurs after the portal and registry have started.
	broken.AuthorizationPolicies[0].AccessListRules = []*acl.RuleConfiguration{{Conditions: []string{"invalid lifecycle condition"}, Action: "allow stop"}}
	failed, err := authcrunch.NewServer(broken, zap.NewNop())
	if err == nil || failed != nil {
		if failed != nil {
			_ = failed.Close()
		}
		t.Fatal("invalid replacement constructed")
	}
	f.authorize(t, token)
	f.login(t)
	replacement, err := authcrunch.NewServer(f.config(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// The embedding host removes the old runtime and drains its requests before Close.
	f.mu.Lock()
	f.active = replacement
	f.mu.Unlock()
	var closes sync.WaitGroup
	for range 12 {
		closes.Go(func() {
			if err := old.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	closes.Wait()
	if _, err := old.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
		t.Fatal("disposed root still returned portal")
	}
	if err := oldPortal.BasicAuth(&authproxy.Request{Realm: "local", Secret: base64.StdEncoding.EncodeToString([]byte("alice:" + tests.TestPwd1))}); err == nil {
		t.Fatal("retained portal authenticated through BasicAuth after shutdown")
	}
	recorder := httptest.NewRecorder()
	if err := oldPortal.ServeHTTP(t.Context(), recorder, httptest.NewRequest(http.MethodGet, "https://portal.example.test/auth/login", nil), requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatal("retained portal pointer served after shutdown")
	}
	recorder = httptest.NewRecorder()
	ar := requests.NewAuthorizationRequest()
	if err := oldGate.Authenticate(recorder, httptest.NewRequest(http.MethodGet, "https://portal.example.test/protected", nil), ar); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusServiceUnavailable || ar.Response.Authorized || ar.Response.Bypassed {
		t.Fatal("retained gatekeeper pointer authorized after shutdown")
	}
	f.authorize(t, token) // Access JWTs remain valid with the same persisted signing key.
	f.login(t)
}

func TestE2EServerFailedConstructionCancelsProvider(t *testing.T) {
	f := newServerLifecycleFixture(t)
	token := f.login(t)
	entered, canceled := make(chan struct{}), make(chan struct{})
	abort := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			close(entered)
			select {
			case <-r.Context().Done():
			case <-abort:
			}
			close(canceled)
			return
		}
		select {
		case <-entered:
		case <-r.Context().Done():
			return
		case <-abort:
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	defer close(abort)
	cfg := f.config(t)
	for _, name := range []string{"first", "second"} {
		params := map[string]any{"realm": name, "driver": "generic", "client_id": "client", "client_secret": "synthetic", "base_auth_url": upstream.URL, "metadata_url": upstream.URL + "/" + name, "tls_insecure_skip_verify": true}
		if name == "first" {
			params["delay_start"] = 1
		}
		cfg.IdentityProviders = append(cfg.IdentityProviders, &idp.IdentityProviderConfig{Name: name, Kind: "oauth", Params: params})
	}
	done := make(chan error, 1)
	go func() {
		server, err := authcrunch.NewServer(cfg, zap.NewNop())
		if server != nil {
			_ = server.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("failing upstream constructed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed construction did not return")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("earlier provider request survived failed construction")
	}
	f.authorize(t, token)
	f.login(t)
}
