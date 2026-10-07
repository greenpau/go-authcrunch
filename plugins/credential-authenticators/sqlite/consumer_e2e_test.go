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
	"encoding/json"
	"errors"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite/parser"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestE2ESQLiteCredentialsGatekeeper(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := parser.NewSQLiteCredentialsConfigFromDirectives([]string{"name keys", "realm staff", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "credentials.db")}), "timeout 500ms"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored credentials.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	writer, err := credentials.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	issue := func(roles []string) string {
		t.Helper()
		key, err := writer.Issue(t.Context(), "alice", "alice@example.test", roles, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key := issue([]string{"viewer"})
	denied := issue([]string{"unprivileged"})
	backend, err := credentials.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	gate, err := authz.NewGatekeeper(&authz.PolicyConfig{Name: "sqlite-credentials", AuthRedirectDisabled: true,
		RawCryptoKeyStoreConfig: []string{"crypto key verify synthetic-sqlite-credentials-verification-key-0123456789"},
		AuthProxyRawConfig:      []string{"api key auth realm staff portal keys", "basic auth realm staff portal keys"},
		AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.AddAuthenticators([]authproxy.Authenticator{backend}); err != nil {
		t.Fatal(err)
	}
	if err := gate.HasAuthProxies(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := requests.NewAuthorizationRequest()
		err := gate.Authenticate(w, r, ar)
		if errors.Is(err, autherrors.ErrAccessNotAllowed) || errors.Is(err, autherrors.ErrAccessNotAllowedByPathACL) {
			return
		}
		if err != nil || !ar.Response.Authorized {
			http.Error(w, "denied", 401)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	check := func(key, realm, method string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Auth-Realm", realm)
		if method == "basic" {
			req.Header.Set("Authorization", "Basic "+key)
		} else {
			req.Header.Set("X-API-Key", key)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s status=%d want=%d", method, resp.StatusCode, want)
		}
	}
	check(key, "staff", "api", 204)
	check(key, "staff", "api", 204)
	check(key, "staff", "basic", 401)
	check(key, "other", "api", 401)
	check("invalid", "staff", "api", 401)
	check(denied, "staff", "api", 403)
	if err := writer.Revoke(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	check(key, "staff", "api", 401)
	key = issue([]string{"viewer"})
	check(key, "staff", "api", 204)
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	check(key, "staff", "api", 401)
}
