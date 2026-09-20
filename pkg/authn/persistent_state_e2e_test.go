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
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	stateparser "github.com/greenpau/go-authcrunch/pkg/state/parser"
	"github.com/greenpau/go-authcrunch/pkg/user"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EPortalPersistentSessionSerializationFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal(err)
	}
	identityStore, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "persistent-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err = identityStore.Configure(); err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(PortalParameters{
		Config: &PortalConfig{Name: "persistent-e2e", IdentityStores: []string{"persistent-local"}, RawCryptoKeyStoreConfig: []string{"crypto default autogenerate tag persistent-e2e"}},
		Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{identityStore},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer portal.Close()

	stateDir := filepath.Join(t.TempDir(), "runtime state")
	stateConfig, err := stateparser.NewStateConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"directory", stateDir})})
	if err != nil {
		t.Fatal(err)
	}
	storage, err := state.Open(stateConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	binding, err := state.Binding(portal.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = portal.ConfigurePersistentState(storage, binding); err != nil {
		t.Fatal(err)
	}

	basicSecret := base64.StdEncoding.EncodeToString([]byte("alice:" + tests.TestPwd1))
	healthyBasic := &authproxy.Request{Realm: "local", Address: "198.51.100.10", Secret: basicSecret}
	if err = portal.BasicAuth(healthyBasic); err != nil || healthyBasic.Response.Payload == "" {
		t.Fatalf("healthy persistent portal BasicAuth failed: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "access=must-not-escape; Secure; HttpOnly")
		if serveErr := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); serveErr != nil {
			t.Errorf("ServeHTTP returned error: %v", serveErr)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	request := func() *http.Response {
		t.Helper()
		resp, requestErr := client.Get(server.URL + "/auth/login")
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return resp
	}
	healthyResponse := request()
	_, err = io.Copy(io.Discard, io.LimitReader(healthyResponse.Body, 1<<20))
	healthyResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if healthyResponse.StatusCode != http.StatusOK {
		t.Fatalf("healthy persistent portal status %d, want %d", healthyResponse.StatusCode, http.StatusOK)
	}

	id := strings.Repeat("s", 32)
	u, err := user.NewUser(map[string]any{"sub": "alice", "jti": id, "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	u.Claims.Metadata = map[string]any{"unsupported": make(chan struct{})}
	if err = portal.sessions.Add(id, u); err == nil {
		t.Fatal("unsupported session state was accepted")
	}
	if err = storage.Err(); err != nil {
		t.Fatal("test requires a healthy store with a failed component", err)
	}

	failedResponse := request()
	_, err = io.Copy(io.Discard, io.LimitReader(failedResponse.Body, 1<<20))
	failedResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if failedResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", failedResponse.StatusCode, http.StatusServiceUnavailable)
	}
	if len(failedResponse.Cookies()) != 0 {
		t.Fatal("credential cookie escaped failed portal response")
	}

	failedBasic := &authproxy.Request{Realm: "local", Address: "198.51.100.11", Secret: basicSecret}
	err = portal.BasicAuth(failedBasic)
	if err != autherrors.ErrBasicAuthFailed || failedBasic.Response.Payload != "" {
		t.Fatalf("BasicAuth returned error %v or a credential after persistence failure", err)
	}
}
