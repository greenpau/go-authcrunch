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
	"context"
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
	authcrunch "github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
	ticketparser "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
	"go.uber.org/zap"
)

type rootTicketProvider struct {
	*tickets.Provider
	mu                 sync.Mutex
	proof              requests.ExternalIdentity
	configures, closes int
}

func (p *rootTicketProvider) Configure() error {
	p.mu.Lock()
	p.configures++
	p.mu.Unlock()
	return p.Provider.Configure()
}
func (p *rootTicketProvider) Close() error {
	p.mu.Lock()
	p.closes++
	p.mu.Unlock()
	return p.Provider.Close()
}
func (p *rootTicketProvider) Login(ctx context.Context, r *http.Request) (*idp.HTTPLoginResult, error) {
	result, err := p.Provider.Login(ctx, r)
	if err == nil && result.Identity != nil {
		p.mu.Lock()
		p.proof = result.ExternalIdentity
		p.mu.Unlock()
	}
	return result, err
}
func (p *rootTicketProvider) untouched(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.configures != 0 || p.closes != 0 {
		t.Fatal("root configured or closed borrowed ticket provider")
	}
}
func (p *rootTicketProvider) evidence() requests.ExternalIdentity {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proof
}

func TestE2EServerExternalSQLiteTicketProvider(t *testing.T) {
	for _, mount := range []string{"/", "/tenant/auth"} {
		t.Run(mount, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			var root *authcrunch.Server
			var provider *rootTicketProvider
			var issuerProvider *tickets.Provider
			var rootMu sync.RWMutex
			issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rootMu.RLock()
				defer rootMu.RUnlock()
				user, password, ok := r.BasicAuth()
				if r.URL.Path != "/login" || !ok || user != "alice" || password != "synthetic-ticket-issuer-password" {
					http.Error(w, "denied", 401)
					return
				}
				// Authentication chooses the trusted subject and roles. Never echo
				// or follow a browser-selected callback destination.
				issued, err := issuerProvider.Issue(r.Context(), r.URL.Query().Get("request"), &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
				if err != nil {
					http.Error(w, "denied", 401)
					return
				}
				target := issuerProvider.CallbackURL() + "?" + url.Values{"state": {r.URL.Query().Get("request")}, "ticket": {issued}}.Encode()
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Referrer-Policy", "no-referrer")
				http.Redirect(w, r, target, 303)
			}))
			defer issuer.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rootMu.RLock()
				defer rootMu.RUnlock()
				name := r.Header.Get("X-Fixture-Portal")
				if name == "" {
					name = "first"
				}
				portal, err := root.GetPortalByName(name)
				if err != nil {
					http.Error(w, "unavailable", 503)
					return
				}
				if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
					t.Error(err)
				}
			}))
			defer func() {
				server.Close()
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
			backend, err := ticketparser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm application", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "tickets.db")}), "public_origin " + server.URL, "issuer_url " + issuer.URL + "/login", "base_path " + mount, "cookie_name APP_TICKET_BINDING"})
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err := idp.NewExternalIdentityProviderConfig(backend.Name, "sqlite-ticket", "ticket", backend.Realm, backend)
			if err != nil {
				t.Fatal(err)
			}
			open := func() {
				t.Helper()
				p, err := tickets.New(t.Context(), backend)
				if err != nil {
					t.Fatal(err)
				}
				provider = &rootTicketProvider{Provider: p}
				issuerProvider, err = tickets.New(t.Context(), backend)
				if err != nil {
					t.Fatal(err)
				}
			}
			open()
			rootConfig := func(requireMFA bool) *authcrunch.Config {
				t.Helper()
				config := &authcrunch.Config{State: &state.Config{Directory: filepath.Join(dir, "state")}, ExternalIdentityProviders: []*idp.ExternalIdentityProviderConfig{descriptor}}
				for _, name := range []string{"first", "second"} {
					actions := []string{"add role app/" + name}
					if requireMFA {
						actions = append(actions, "require totp")
					}
					config.AuthenticationPortals = append(config.AuthenticationPortals, &authn.PortalConfig{Name: name, IdentityProviders: []string{"tickets"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + externalIdentityKey}, UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"exact match realm application"}, Actions: actions}}})
				}
				raw, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				var restored authcrunch.Config
				if err := json.Unmarshal(raw, &restored); err != nil {
					t.Fatal(err)
				}
				return &restored
			}
			construct := func(requireMFA bool) *authcrunch.Server {
				t.Helper()
				runtime, err := authcrunch.NewServerWithOptions(rootConfig(requireMFA), zap.NewNop(), authcrunch.ServerOptions{IdentityProviders: map[string]idp.IdentityProvider{"tickets": provider}})
				if err != nil {
					t.Fatal(err)
				}
				return runtime
			}
			if err := rootConfig(false).Validate(); err != nil {
				t.Fatal(err)
			}
			if missing, err := authcrunch.NewServer(rootConfig(false), zap.NewNop()); missing != nil || err == nil {
				t.Fatal("missing ticket binding accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
				t.Fatal("missing provider acquired persistent state")
			}
			root = construct(false)
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
			fetch := func(c *http.Client, target, portal, password string) (*http.Response, string) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), "GET", target, nil)
				if err != nil {
					t.Fatal(err)
				}
				if portal != "" {
					r.Header.Set("X-Fixture-Portal", portal)
				}
				if password != "" {
					r.SetBasicAuth("alice", password)
				}
				response, err := c.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				return response, string(body)
			}
			begin := func(c *http.Client, portal string) string {
				t.Helper()
				response, _ := fetch(c, provider.CallbackURL(), portal, "")
				if response.StatusCode != 302 || !strings.HasPrefix(response.Header.Get("Location"), issuer.URL+"/login?") {
					t.Fatal("ticket begin failed", response.StatusCode)
				}
				if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" {
					t.Fatal("ticket credentials can escape browser cache/referrer")
				}
				var binding *http.Cookie
				for _, c := range response.Cookies() {
					if c.Name != "APP_TICKET_BINDING" {
						continue
					}
					if binding != nil {
						t.Fatal("duplicate ticket binding cookie")
					}
					binding = c
				}
				if binding == nil || binding.Path != strings.TrimSuffix(mount, "/")+"/provider/application" || !binding.Secure || !binding.HttpOnly || binding.Domain != "" || binding.SameSite != http.SameSiteLaxMode || binding.MaxAge != 300 {
					t.Fatal("ticket cookie binding changed")
				}
				return response.Header.Get("Location")
			}
			issue := func(c *http.Client, location string) string {
				t.Helper()
				response, _ := fetch(c, location, "", "synthetic-ticket-issuer-password")
				if response.StatusCode != 303 {
					t.Fatal("trusted issuance failed", response.StatusCode)
				}
				return response.Header.Get("Location")
			}
			verify := func(response *http.Response, portal string) jwt.MapClaims {
				t.Helper()
				if response.StatusCode != 303 {
					t.Fatal("ticket root completion failed", response.StatusCode)
				}
				raw := strings.TrimPrefix(response.Header.Get("Authorization"), "Bearer ")
				token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(externalIdentityKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
				if err != nil || !token.Valid {
					t.Fatal("invalid root ticket JWT", err)
				}
				claims := token.Claims.(jwt.MapClaims)
				if claims["sub"] != "alice" || claims["id"] == nil || claims["id"] == "" || claims["id"] == claims["sub"] || claims["origin"] != "application" || claims["email"] != "alice@example.test" || claims["nonce"] == nil || claims["nonce"] == "" {
					t.Fatal("incorrect verified ticket identity")
				}
				methods, ok := claims["amr"].([]any)
				if !ok || len(methods) != 1 || methods[0] != "federated" {
					t.Fatal("incorrect ticket authentication evidence")
				}
				roles, ok := claims["roles"].([]any)
				if !ok {
					t.Fatal("missing transformed roles")
				}
				found := false
				for _, role := range roles {
					if role == "app/"+portal {
						found = true
					}
				}
				if !found {
					t.Fatal("selected portal transform bypassed")
				}
				if claims["exp"].(float64) <= claims["iat"].(float64) {
					t.Fatal("invalid token lifetime")
				}
				return claims
			}
			login := func(c *http.Client, portal string) jwt.MapClaims {
				t.Helper()
				callback := issue(c, begin(c, portal))
				response, _ := fetch(c, callback, portal, "")
				return verify(response, portal)
			}
			first := browser()
			page, body := fetch(first, server.URL+strings.TrimSuffix(mount, "/")+"/login", "first", "")
			if page.StatusCode != 200 || !strings.Contains(body, "provider/application") {
				t.Fatal("root ticket option missing")
			}
			location := begin(first, "first")
			for _, password := range []string{"", "wrong"} {
				response, _ := fetch(first, location, "", password)
				if response.StatusCode != 401 || response.Header.Get("Authorization") != "" {
					t.Fatal("unverified issuer accepted")
				}
			}
			callback := issue(first, location)
			// Invalid selection is rejected before opening a candidate state owner,
			// and cannot disturb the live shared provider or spend its pending ticket.
			invalid := rootConfig(false)
			invalid.AuthenticationPortals[0].IdentityProviders = []string{"missing"}
			if candidate, err := authcrunch.NewServerWithOptions(invalid, zap.NewNop(), authcrunch.ServerOptions{IdentityProviders: map[string]idp.IdentityProvider{"tickets": provider}}); candidate != nil || err == nil {
				t.Fatal("unknown provider candidate accepted")
			}
			provider.untouched(t)
			response, _ := fetch(first, callback, "first", "")
			initial := verify(response, "first")
			again := login(first, "first")
			other := login(browser(), "second")
			if again["id"] != initial["id"] || other["id"] != initial["id"] || again["nonce"] == initial["nonce"] {
				t.Fatal("shared provider lost identity or reused login nonce")
			}
			proof := provider.evidence()
			attached, err := provider.IdentityAttachment().Store()
			if err != nil {
				t.Fatal(err)
			}
			if err := attached.WithRefreshIdentity(t.Context(), proof.Evidence, func(identity.RefreshIdentity) error { return nil }); err != nil {
				t.Fatal("live external proof rejected", err)
			}
			replace := func(reopen, requireMFA bool) {
				t.Helper()
				rootMu.Lock()
				defer rootMu.Unlock()
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
				provider.untouched(t)
				if reopen {
					if err := provider.Provider.Close(); err != nil {
						t.Fatal(err)
					}
					if err := issuerProvider.Close(); err != nil {
						t.Fatal(err)
					}
					open()
				}
				root = construct(requireMFA)
			}
			// Keep a pending ticket across both a root-only restart and a complete
			// provider replacement. Ticket durability and local ID lifetime differ.
			pending := issue(first, begin(first, "first"))
			replace(false, false)
			response, _ = fetch(first, pending, "first", "")
			same := verify(response, "first")
			if same["id"] != initial["id"] {
				t.Fatal("root-only reconstruction replaced borrowed attachment")
			}
			pending = issue(first, begin(first, "first"))
			replace(true, false)
			replacement, err := provider.IdentityAttachment().Store()
			if err != nil {
				t.Fatal(err)
			}
			if err := replacement.WithRefreshIdentity(t.Context(), proof.Evidence, func(identity.RefreshIdentity) error { return nil }); err == nil {
				t.Fatal("retired implicit identity proof survived provider replacement")
			}
			response, _ = fetch(first, pending, "first", "")
			fresh := verify(response, "first")
			if fresh["id"] == initial["id"] {
				t.Fatal("fresh provider incorrectly persisted implicit local identity")
			}
			if response, _ := fetch(first, pending, "first", ""); response.Header.Get("Authorization") != "" || response.StatusCode < 400 {
				t.Fatal("spent ticket accepted after restart")
			}
			// A ticket supplies no actual TOTP factor and cannot satisfy a stronger
			// current portal policy through asserted roles or private attachment IDs.
			replace(false, true)
			denied := issue(first, begin(first, "first"))
			response, _ = fetch(first, denied, "first", "")
			if response.StatusCode != 403 || response.Header.Get("Authorization") != "" {
				t.Fatal("ticket bypassed required local factor", response.StatusCode)
			}
			response, _ = fetch(first, denied, "first", "")
			if response.StatusCode < 400 || response.Header.Get("Authorization") != "" {
				t.Fatal("policy failure restored consumed ticket")
			}
			provider.untouched(t)
		})
	}
}
