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

package authn_test

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	passwordparser "github.com/greenpau/go-authcrunch/pkg/identity/password/parser"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newArgon2PortalE2E(t *testing.T, path string, users []*local.User) *oidcE2EFixture {
	t.Helper()
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": path, "users": users}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal("could not configure password imports:", err)
	}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	portal, err := authn.NewPortal(authn.PortalParameters{
		Config: &authn.PortalConfig{Name: "argon2", IdentityStores: []string{"local"}, CookieConfig: cookie.NewConfig(), API: &authn.APIConfig{ProfileEnabled: true}, RawCryptoKeyStoreConfig: []string{e2eRSAKey}, RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: origin, BasePath: "/auth", BodyTransportEnabled: true}},
		Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("password portal request failed")
		}
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &oidcE2EFixture{server: server, client: client, issuer: origin + "/auth"}
	f.close = func() { server.Close(); portal.Close() }
	t.Cleanup(f.close)
	return f
}

func argon2PortalLogin(t *testing.T, f *oidcE2EFixture, username, password string, allowed bool) *authclient.Credentials {
	t.Helper()
	client, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", Username: username, Password: password, RefreshTransport: "body"}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal("could not configure password client")
	}
	credentials, err := client.Authenticate(t.Context())
	if !allowed {
		var status *authclient.HTTPError
		if credentials != nil || !errors.As(err, &status) || status.StatusCode != http.StatusUnauthorized {
			t.Fatal("invalid credential was not rejected with 401")
		}
		return nil
	}
	if err != nil || credentials == nil || credentials.AccessToken == "" || credentials.RefreshToken == "" {
		t.Fatal("valid password did not produce credentials")
	}
	loginIdentityClaims(t, f, credentials.AccessToken, username)
	response := f.request(t, "GET", "/whoami", nil, http.Header{"Authorization": {"Bearer " + credentials.AccessToken}})
	oidcE2EStatus(t, response, http.StatusOK)
	return credentials
}

func TestE2EArgon2PortalPasswords(t *testing.T) {
	c, err := passwordparser.NewPasswordHashConfigFromDirectives([]string{"algorithm argon2", "memory 1024", "iterations 2", "parallelism 2"})
	if err != nil {
		t.Fatal(err)
	}
	password, err := identity.NewPasswordWithConfig(tests.TestPwd1, "generic", c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	users := []*local.User{
		{Username: "alice", EmailAddress: "alice@example.test", Password: password.EncodedHash(), PasswordOverwriteEnabled: true, Roles: []string{"authp/user"}},
		{Username: "bob", EmailAddress: "bob@example.test", Password: tests.TestPwd2Hash(t), Roles: []string{"authp/user"}},
	}
	first := newArgon2PortalE2E(t, path, users)
	oidcE2EStatus(t, passwordAttemptBasic(t, first, "198.51.100.10", tests.TestPwd1), http.StatusSeeOther)
	oidcE2EStatus(t, first.request(t, http.MethodGet, "/whoami", nil, nil), http.StatusOK)
	denied := passwordAttemptBasic(t, first, "198.51.100.10", "incorrect")
	oidcE2EStatus(t, denied, http.StatusUnauthorized)
	assertNoPasswordCredential(t, denied)
	first.loginBrowser(t)
	argon2PortalLogin(t, first, "alice", tests.TestPwd1, true)
	argon2PortalLogin(t, first, "alice", "incorrect", false)
	argon2PortalLogin(t, first, "missing", "incorrect", false)
	argon2PortalLogin(t, first, "alice", password.EncodedHash(), false)
	argon2PortalLogin(t, first, "bob", tests.TestPwd2, true)
	first.close()
	// Reapply identical configured imports in a new runtime; keep one active hash.
	second := newArgon2PortalE2E(t, path, users)
	credentials := argon2PortalLogin(t, second, "alice", tests.TestPwd1, true)
	native := *second
	nativeClient := *second.client
	nativeClient.Jar = nil
	native.client = &nativeClient
	rotated := native.jsonRequest(t, "/api/refresh_token", map[string]any{"refresh_token": credentials.RefreshToken}, "")
	oidcE2EStatus(t, rotated, http.StatusOK)
	refreshToken := loginIdentityResponse(t, rotated).RefreshToken
	if refreshToken == "" {
		t.Fatal("refresh did not rotate the native credential")
	}
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range db.Users {
		if user.Username == "alice" && (len(user.Passwords) != 1 || user.Passwords[0].Algorithm != "argon2" || user.Passwords[0].Hash != password.Hash) {
			t.Fatal("reload changed the configured password")
		}
	}
	// A fresh database writer changes the password; the running portal observes it.
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", OldPassword: tests.TestPwd1, Password: tests.TestPwd2}}); err != nil {
		t.Fatal("could not change Argon2 password")
	}
	argon2PortalLogin(t, second, "alice", tests.TestPwd1, false)
	argon2PortalLogin(t, second, "alice", tests.TestPwd2, true)
	reopened, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range reopened.Users {
		if user.Username == "alice" && user.Passwords[0].Algorithm != "argon2" {
			t.Fatal("password change downgraded Argon2")
		}
	}
	refreshed := native.jsonRequest(t, "/api/refresh_token", map[string]any{"refresh_token": refreshToken}, "")
	oidcE2EStatus(t, refreshed, http.StatusUnauthorized)
}

func TestE2EPasswordConfigurationRejectsInvalidImport(t *testing.T) {
	// Valid Argon2 and bcrypt hashes provide the shapes; each change must be
	// rejected during shared store provisioning before an identity is persisted.
	const validArgon2 = "argon2:$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"
	validBcrypt := tests.TestPwd1Hash(t)
	for _, candidate := range []string{
		strings.Replace(validArgon2, "v=19", "v=16", 1),
		strings.Replace(validArgon2, "m=256", "m=262145", 1),
		strings.Replace(validArgon2, "c29tZXNhbHQ", "malformed!", 1),
		strings.Replace(validBcrypt, "$2a$", "$2z$", 1),
		strings.Replace(validBcrypt, "$2a$", "$2a!", 1),
	} {
		path := filepath.Join(t.TempDir(), "users.json")
		store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{
			"realm": "local", "path": path,
			"users": []*local.User{{Username: "alice", EmailAddress: "alice@example.test", Password: candidate}},
		}}, zap.NewNop())
		if err != nil {
			t.Fatal("could not construct shared store configuration")
		}
		if err := store.Configure(); err == nil || strings.Contains(err.Error(), candidate) {
			t.Fatal("invalid import was accepted or disclosed in the error")
		}
		db, err := identity.NewDatabase(path)
		if err != nil || len(db.Users) != 0 {
			t.Fatal("invalid import persisted an identity")
		}
	}
}
