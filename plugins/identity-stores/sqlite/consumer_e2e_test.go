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
	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite/parser"
	"go.uber.org/zap"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const signingKey = "synthetic-sqlite-identity-signing-secret-0123456789"
const password = "Synthetic-identity-password-2026!"

func newPortal(t *testing.T, store ids.IdentityStore, requireFactor bool) (*httptest.Server, *http.Client) {
	t.Helper()
	cfg := &authn.PortalConfig{Name: "sqlite-identities", IdentityStores: []string{"accounts"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + signingKey}}
	if requireFactor {
		cfg.UserTransformerConfigs = []*transformer.Config{{Matchers: []string{"exact match realm staff"}, Actions: []string{"require totp"}}}
	}
	portal, err := authn.NewPortal(authn.PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("portal handler failed", err)
		}
	}))
	t.Cleanup(func() { server.Close(); portal.Close() })
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return server, client
}
func verifyToken(t *testing.T, raw string) {
	t.Helper()
	token, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) { return []byte(signingKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
	if err != nil || !token.Valid {
		t.Fatal("invalid signed credential", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "alice" || claims["origin"] != "staff" {
		t.Fatal("wrong authenticated identity")
	}
	methods := claims["amr"].([]any)
	if len(methods) != 1 || methods[0] != "pwd" {
		t.Fatal("missing password evidence")
	}
}
func TestE2ESQLiteIdentityStorePortal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := parser.NewSQLiteIdentityStoreConfigFromDirectives([]string{"name accounts", "realm staff", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "accounts.db")}), "timeout 5s"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored accounts.Config
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Create(t.Context(), &accounts.Account{Username: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}}, password); err != nil {
		t.Fatal(err)
	}
	server, client := newPortal(t, store, false)
	basic := func(client *http.Client, url, realm, secret string, want int) string {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "GET", url+"/auth/basic/login/"+realm, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("alice", secret)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("basic status=%d want=%d", response.StatusCode, want)
		}
		token := strings.TrimPrefix(response.Header.Get("Authorization"), "Bearer ")
		if want != 303 && token != "" {
			t.Fatal("rejected request minted token")
		}
		return token
	}
	verifyToken(t, basic(client, server.URL, "staff", password, 303))
	basic(client, server.URL, "staff", "incorrect-password", 401)
	basic(client, server.URL, "other", password, 400)
	native, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL + "/auth", Realm: "staff", Username: "alice@example.test", Password: password}, authclient.Options{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	result, err := native.Authenticate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	verifyToken(t, result.AccessToken)
	// Browser form login follows the actual sandbox and redeems it once.
	browser := server.Client()
	browser.Timeout = 10 * time.Second
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	browser.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	form := func(target string, values url.Values) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", server.URL)
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 303 {
			t.Fatalf("browser form status=%d", resp.StatusCode)
		}
		return resp
	}
	start := form(server.URL+"/auth/login", url.Values{"username": {"ALICE@EXAMPLE.TEST"}, "realm": {"staff"}})
	sandbox := start.Header.Get("Location")
	form(sandbox, url.Values{"secret": {password}})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, sandbox, nil)
	if err != nil {
		t.Fatal(err)
	}
	redemption, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	redemption.Body.Close()
	if redemption.StatusCode != 303 {
		t.Fatalf("browser redemption status=%d", redemption.StatusCode)
	}
	location, err := url.Parse(server.URL + "/auth/portal")
	if err != nil {
		t.Fatal(err)
	}
	token := ""
	for _, cookie := range browser.Jar.Cookies(location) {
		if cookie.Name == "AUTHP_ACCESS_TOKEN" {
			token = cookie.Value
		}
	}
	verifyToken(t, token)

	other, err := accounts.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.DisableUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	basic(client, server.URL, "staff", password, 401)
	if err := other.EnableUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := other.SetPassword(t.Context(), "alice", "alice@example.test", "Replacement-password-2026!"); err != nil {
		t.Fatal(err)
	}
	basic(client, server.URL, "staff", password, 401)
	verifyToken(t, basic(client, server.URL, "staff", "Replacement-password-2026!", 303))
	policyServer, policyClient := newPortal(t, store, true)
	basic(policyClient, policyServer.URL, "staff", "Replacement-password-2026!", 403)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	basic(client, server.URL, "staff", "Replacement-password-2026!", 401)
	reopened, err := accounts.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted, restartClient := newPortal(t, reopened, false)
	verifyToken(t, basic(restartClient, restarted.URL, "staff", "Replacement-password-2026!", 303))
}

// Force a real committed credential mutation after verification and before
// portal signing. This retains the actual backend transaction capability.
type revokingStore struct{ *accounts.Store }

func (s *revokingStore) Request(op operator.Type, r *requests.Request) error {
	if err := s.Store.Request(op, r); err != nil {
		return err
	}
	if op == operator.Authenticate {
		return s.Store.DisableUser(r.User.Username, r.User.Email)
	}
	return nil
}
func TestE2ESQLiteIdentityStoreRechecksBeforeSigning(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := parser.NewSQLiteIdentityStoreConfigFromDirectives([]string{"name accounts", "realm staff", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "identities.db")}), "timeout 5s"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Create(t.Context(), &accounts.Account{Username: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}}, password); err != nil {
		t.Fatal(err)
	}
	server, client := newPortal(t, &revokingStore{Store: store}, false)
	req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/auth/basic/login/staff", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", password)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 || response.Header.Get("Authorization") != "" {
		t.Fatal("revoked credential minted token")
	}
}
