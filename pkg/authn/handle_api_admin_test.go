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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func TestAdminAPIExternalAccountSelector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "member", Email: "member@example.test", Password: tests.TestPwd1Hash(t)}}); err != nil {
		t.Fatal(err)
	}
	backend, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "accounts", Kind: "local", Params: map[string]any{"path": path, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Configure(); err != nil {
		t.Fatal(err)
	}
	external, err := backend.(attachment.Store).ResolveExternalAccount(t.Context(), identity.ExternalAccount{Provider: "provider", Kind: "oauth", Issuer: "https://issuer.test", Subject: "subject", Email: "member@example.test"}, true)
	if err != nil {
		t.Fatal(err)
	}
	p := &Portal{logger: zap.NewNop(), identityStores: []ids.IdentityStore{backend}}
	for _, tc := range []struct {
		name, operation, realm, username string
		email                            any
		includeEmail                     bool
		status                           int
	}{
		{name: "omitted email", status: http.StatusOK},
		{name: "empty email", email: "", includeEmail: true, status: http.StatusOK},
		{name: "provider display email", email: "member@example.test", includeEmail: true, status: http.StatusInternalServerError},
		{name: "boolean email", email: false, includeEmail: true, status: http.StatusBadRequest},
		{name: "null email", includeEmail: true, status: http.StatusBadRequest},
		{name: "array email", email: []string{}, includeEmail: true, status: http.StatusBadRequest},
		{name: "ordinary account still needs email", username: "member", status: http.StatusInternalServerError},
		{name: "unknown realm", realm: "missing", status: http.StatusBadRequest},
		{name: "creation needs email", operation: "add", status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.operation == "" {
				tc.operation = "info"
			}
			if tc.realm == "" {
				tc.realm = "local"
			}
			if tc.username == "" {
				tc.username = external.Identity.Username
			}
			fields := map[string]any{"username": tc.username}
			if tc.includeEmail {
				fields["email"] = tc.email
			}
			body, err := json.Marshal(map[string]any{"realm": tc.realm, "operation": tc.operation, "user": fields})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/api/server/user", strings.NewReader(string(body)))
			res := httptest.NewRecorder()
			if err := p.handleAPICrudUser(req.Context(), res, req, requests.NewRequest(), nil); err != nil {
				t.Fatal(err)
			}
			if res.Code != tc.status {
				t.Fatalf("HTTP %d, want %d", res.Code, tc.status)
			}
			if tc.status == http.StatusOK {
				var record identity.User
				if err := json.Unmarshal(res.Body.Bytes(), &record); err != nil || record.ID != external.Evidence.UserID {
					t.Fatal("selector did not return the external local identity", err)
				}
			}
		})
	}
}

func TestAdminAPIRequestBodyLimit(t *testing.T) {
	p := &Portal{logger: zap.NewNop()}
	type handler func(context.Context, http.ResponseWriter, *http.Request, *requests.Request, *user.User) error
	for _, tc := range []struct {
		name string
		call handler
	}{
		{"realms", p.handleAPIListRealms},
		{"users", p.handleAPIListUsers},
		{"user", p.handleAPICrudUser},
		{"info", p.handleAPIRealmInfo},
		{"reload", p.handleAPIReloadRealm},
	} {
		t.Run(tc.name+" rejects oversized JSON", func(t *testing.T) {
			body := `{"realm":"` + strings.Repeat("x", int(maxAdminAPIRequestBodySize)) + `"}`
			req := httptest.NewRequest(http.MethodPost, "/auth/api/server/"+tc.name, strings.NewReader(body))
			res := httptest.NewRecorder()
			if err := tc.call(req.Context(), res, req, requests.NewRequest(), nil); err != nil {
				t.Fatal(err)
			}
			if res.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("got status %d, want %d", res.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}

	t.Run("accepts JSON at limit", func(t *testing.T) {
		const envelope = `{"query":""}`
		body := `{"query":"` + strings.Repeat("x", int(maxAdminAPIRequestBodySize)-len(envelope)) + `"}`
		if int64(len(body)) != maxAdminAPIRequestBodySize {
			t.Fatal("test body does not exercise exact limit")
		}
		req := httptest.NewRequest(http.MethodPost, "/auth/api/server/realms", strings.NewReader(body))
		res := httptest.NewRecorder()
		if err := p.handleAPIListRealms(req.Context(), res, req, requests.NewRequest(), nil); err != nil {
			t.Fatal(err)
		}
		if res.Code != http.StatusOK {
			t.Fatalf("got status %d, want %d", res.Code, http.StatusOK)
		}
	})
}
