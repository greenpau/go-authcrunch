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
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	authcrunch "github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
	ticketparser "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
)

// The external consumer uses the public root, parser and runtime options. It
// never constructs a second local store for the provider or reaches into a
// portal's identity/session internals.
func TestE2EServerExternalSQLiteTicketAttachment(t *testing.T) {
	const mount = "/tenant/auth"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	accountsPath := filepath.Join(dir, "accounts.json")
	db, err := identity.NewDatabase(accountsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal(err)
	}
	var localID string
	for _, u := range db.Users {
		if u.Username == "alice" {
			localID = u.ID
		}
	}
	if localID == "" {
		t.Fatal("local account fixture is missing")
	}
	var root *authcrunch.Server
	var provider *rootTicketProvider
	var issuerProvider *tickets.Provider
	var mu sync.RWMutex
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		username, password, ok := r.BasicAuth()
		if r.URL.Path != "/login" || !ok || username != "alice" || password != "synthetic-attached-issuer-password" {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		issued, err := issuerProvider.Issue(r.Context(), r.URL.Query().Get("request"), &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "External Alice", Roles: []string{"authp/user"}})
		if err != nil {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, issuerProvider.CallbackURL()+"?"+url.Values{"state": {r.URL.Query().Get("request")}, "ticket": {issued}}.Encode(), http.StatusSeeOther)
	}))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		if r.URL.Path == "/protected" {
			gate, err := root.GetGatekeeperByName("policy")
			if err != nil {
				http.Error(w, "unavailable", 503)
				return
			}
			ar := requests.NewAuthorizationRequest()
			if err := gate.Authenticate(w, r, ar); err != nil {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			if !ar.Response.Authorized {
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		name := r.Header.Get("X-Fixture-Portal")
		if name == "" {
			name = "first"
		}
		portal, err := root.GetPortalByName(name)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		if err := portal.ServeHTTPAt(r.Context(), w, r, requests.NewRequest(), mount); err != nil {
			t.Error("attached root portal request failed")
		}
	}))
	defer func() {
		server.Close()
		issuer.Close()
		if root != nil {
			_ = root.Close()
		}
		if provider != nil {
			_ = provider.Provider.Close()
		}
		if issuerProvider != nil {
			_ = issuerProvider.Close()
		}
	}()
	backend, err := ticketparser.NewSQLiteTicketProviderConfigFromDirectives([]string{
		"name tickets", "realm application", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "tickets.db")}),
		"public_origin " + server.URL, "issuer_url " + issuer.URL + "/login", "base_path " + mount,
		"attach to local identity store accounts",
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := idp.NewExternalIdentityProviderConfig(backend.Name, "sqlite-ticket", "ticket", backend.Realm, backend)
	if err != nil {
		t.Fatal(err)
	}
	issuerProvider, err = tickets.New(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	config := &authcrunch.Config{
		State:                     &state.Config{Directory: filepath.Join(dir, "state")},
		IdentityStores:            []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local", Params: map[string]any{"path": accountsPath, "realm": "local"}}},
		ExternalIdentityProviders: []*idp.ExternalIdentityProviderConfig{descriptor},
		AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + externalIdentityKey}, ValidateBearerHeader: true, AuthRedirectDisabled: true,
			AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}},
	}
	for _, name := range []string{"first", "second"} {
		config.AuthenticationPortals = append(config.AuthenticationPortals, &authn.PortalConfig{Name: name, IdentityProviders: []string{"tickets"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + externalIdentityKey}})
	}
	declaration, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	open := func() {
		t.Helper()
		var restored authcrunch.Config
		if err := json.Unmarshal(declaration, &restored); err != nil {
			t.Fatal(err)
		}
		p, err := tickets.New(t.Context(), backend)
		if err != nil {
			t.Fatal(err)
		}
		provider = &rootTicketProvider{Provider: p}
		root, err = authcrunch.NewServerWithOptions(&restored, zap.NewNop(), authcrunch.ServerOptions{
			IdentityProviders: map[string]idp.IdentityProvider{"tickets": provider}, IdentityProviderAttachmentStores: map[string]string{"tickets": "accounts"},
		})
		if err != nil {
			t.Fatal("cannot compose explicit root attachment", err)
		}
	}
	open()
	browser := func() *http.Client {
		t.Helper()
		c := *server.Client()
		c.Timeout = 10 * time.Second
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c.Jar, err = cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		return &c
	}
	fetch := func(c *http.Client, target, portal, authorization string, want int) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal("cannot construct fixture request")
		}
		r.Header.Set("X-Fixture-Portal", portal)
		if strings.HasPrefix(target, issuer.URL+"/") {
			r.SetBasicAuth("alice", "synthetic-attached-issuer-password")
		}
		if authorization != "" {
			r.Header.Set("Authorization", "Bearer "+authorization)
		}
		response, err := c.Do(r)
		if err != nil {
			t.Fatal("attached provider TLS request failed")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		response.Body.Close()
		if err != nil || len(body) > 1<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatal("attached provider response lacked bounded verified TLS")
		}
		if response.StatusCode != want {
			t.Fatalf("attached provider response HTTP %d, want %d", response.StatusCode, want)
		}
		if target != server.URL+"/protected" && response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("ticket flow allowed caching")
		}
		return response
	}
	callback := func(c *http.Client, portal string) string {
		t.Helper()
		begin := fetch(c, provider.CallbackURL(), portal, "", 302)
		location := begin.Header.Get("Location")
		if !strings.HasPrefix(location, issuer.URL+"/login?") {
			t.Fatal("ticket begin escaped trusted issuer")
		}
		issued := fetch(c, location, portal, "", 303)
		location = issued.Header.Get("Location")
		if !strings.HasPrefix(location, provider.CallbackURL()+"?") {
			t.Fatal("issuer escaped provider callback")
		}
		return location
	}
	login := func(c *http.Client, portal string) jwt.MapClaims {
		t.Helper()
		response := fetch(c, callback(c, portal), portal, "", 303)
		raw := strings.TrimPrefix(response.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(externalIdentityKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
		if err != nil || !token.Valid {
			t.Fatal("root did not issue an independently verified JWT")
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["id"] == nil || claims["id"] == "" || claims["sub"] != "alice" || claims["origin"] != "application" || claims["email"] != "alice@example.test" {
			t.Fatal("attached identity claims changed")
		}
		methods, ok := claims["amr"].([]any)
		if !ok || len(methods) != 1 || methods[0] != "federated" {
			t.Fatal("ticket invented local authentication evidence")
		}
		fetch(c, server.URL+"/protected", portal, raw, 204)
		return claims
	}
	client := browser()
	first := login(client, "first")
	if first["id"] == localID || first["id"] == "alice" {
		t.Fatal("provider email matched an existing local identity")
	}
	second := login(browser(), "second")
	if second["id"] != first["id"] {
		t.Fatal("shared root provider used different account stores across portals")
	}
	attached := func() *local.IdentityStore {
		t.Helper()
		s, err := provider.IdentityAttachment().Store()
		if err != nil {
			t.Fatal(err)
		}
		result, ok := s.(*local.IdentityStore)
		if !ok {
			t.Fatal("root attachment is not its concrete local store")
		}
		return result
	}
	var username string
	if err := attached().WithRefreshIdentity(t.Context(), provider.evidence().Evidence, func(current identity.RefreshIdentity) error {
		username = current.Username
		if !current.ExternallyProvisioned || current.Email != "" || len(current.ExternalAccounts) != 1 || current.ExternalAccounts[0].Issuer != backend.IssuerURL || current.ExternalAccounts[0].Subject != "alice" {
			t.Fatal("automatic attachment identity has wrong authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if username == "" || username == "alice" {
		t.Fatal("automatic identity did not retain internal username")
	}
	if _, err := attached().AddUserRoles(username, "", []string{"local/managed"}); err != nil {
		t.Fatal(err)
	}
	managed := login(client, "first")
	roles, ok := managed["roles"].([]any)
	if !ok {
		t.Fatal("local policy roles are missing")
	}
	found := false
	for _, role := range roles {
		if role == "local/managed" {
			found = true
		}
	}
	if !found {
		t.Fatal("external login did not recheck local account policy")
	}
	proof := provider.evidence().Evidence
	previousStore := attached()
	func() {
		mu.Lock()
		defer mu.Unlock()
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		provider.untouched(t)
		if err := provider.Provider.Close(); err != nil {
			t.Fatal(err)
		}
		open()
	}()
	if attached() == previousStore {
		t.Fatal("root replacement reused old local snapshot")
	}
	if err := attached().WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error { return nil }); err != nil {
		t.Fatal("compatible root replacement lost file-bound identity epoch", err)
	}
	after := login(client, "second")
	if after["id"] != first["id"] {
		t.Fatal("explicit file attachment lost identity across provider/root replacement")
	}
	if err := attached().DisableUser(username, ""); err != nil {
		t.Fatal(err)
	}
	denied := callback(client, "first")
	response := fetch(client, denied, "first", "", 401)
	if response.Header.Get("Authorization") != "" {
		t.Fatal("disabled local identity issued a ticket credential")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "AUTHP_ACCESS_TOKEN" && cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("disabled local identity issued an access cookie")
		}
	}
	if err := attached().WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error { return nil }); err == nil {
		t.Fatal("disabled identity retained old evidence")
	}
	if err := attached().EnableUser(username, ""); err != nil {
		t.Fatal(err)
	}
	// The successful ticket commit preceded the disabled-account refusal. The
	// old callback must stay spent after enable; only a newly verified login works.
	fetch(client, denied, "first", "", 401)
	if restored := login(client, "first"); restored["id"] != first["id"] {
		t.Fatal("enable changed the attached identity")
	}
	provider.untouched(t)
}
