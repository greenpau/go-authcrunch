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
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
)

func TestE2ESQLiteTicketPortal(t *testing.T) {
	const secret = "synthetic-ticket-portal-signing-key-0123456789"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[tickets.Provider]
	var portal atomic.Pointer[authn.Portal]
	// The test application owns this authenticated endpoint. The plugin itself
	// exposes issuance only as a trusted Go API, never as an anonymous HTTP route.
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "alice" || password != "synthetic-issuer-password" {
			http.Error(w, "unauthorized", 401)
			return
		}
		p := active.Load()
		q := r.URL.Query()
		if r.URL.Path != "/login" || q.Get("callback") != p.CallbackURL() {
			http.Error(w, "bad request", 400)
			return
		}
		ticket, err := p.Issue(r.Context(), q.Get("request"), &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
		if err != nil {
			http.Error(w, "issuance denied", 401)
			return
		}
		target := p.CallbackURL() + "?" + url.Values{"state": {q.Get("request")}, "ticket": {ticket}}.Encode()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, target, 303)
	}))
	defer issuer.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.Load().ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	cfg, err := parser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm application", fmt.Sprintf("path %q", filepath.Join(dir, "tickets.db")), "public_origin " + server.URL, "base_path /tenant/auth", "issuer_url " + issuer.URL + "/login", "timeout 750ms", "cookie_name APP_TICKET_BINDING"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored tickets.Config
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	provider, err := tickets.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(provider)
	defer func() {
		if p := portal.Load(); p != nil {
			p.Close()
		}
		active.Load().Close()
	}()
	install := func(requireMFA bool) {
		t.Helper()
		actions := []string{"add role app/verified"}
		if requireMFA {
			actions = append(actions, "require totp")
		}
		p, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "ticket-portal", IdentityProviders: []string{"tickets"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + secret}, UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"exact match realm application"}, Actions: actions}}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{active.Load()}})
		if err != nil {
			t.Fatal(err)
		}
		old := portal.Swap(p)
		if old != nil {
			old.Close()
		}
	}
	install(false)
	browser := func() *http.Client {
		t.Helper()
		client := *server.Client()
		client.Timeout = 10 * time.Second
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client.Jar, err = cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		return &client
	}
	fetch := func(client *http.Client, target string, authenticate bool, host string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "GET", target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authenticate {
			req.SetBasicAuth("alice", "synthetic-issuer-password")
		}
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(body)
	}
	begin := func(client *http.Client) string {
		t.Helper()
		resp, _ := fetch(client, active.Load().CallbackURL(), false, "")
		if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), issuer.URL+"/login?") {
			t.Fatal("provider begin", resp.StatusCode)
		}
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("unsafe begin caching/referrer policy")
		}
		return resp.Header.Get("Location")
	}
	issue := func(client *http.Client, target string) string {
		t.Helper()
		resp, _ := fetch(client, target, true, "")
		if resp.StatusCode != 303 {
			t.Fatal("trusted issuer", resp.StatusCode)
		}
		return resp.Header.Get("Location")
	}
	verify := func(resp *http.Response) {
		t.Helper()
		if resp.StatusCode != 303 || resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("portal completion", resp.StatusCode)
		}
		raw := strings.TrimPrefix(resp.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(secret), nil }, jwt.WithValidMethods([]string{"HS512"}))
		if err != nil || !token.Valid {
			t.Fatal("invalid portal JWT", err)
		}
		claims := token.Claims.(jwt.MapClaims)
		if claims["sub"] != "alice" || claims["origin"] != "application" || claims["email"] != "alice@example.test" {
			t.Fatal("wrong provider identity")
		}
		methods := claims["amr"].([]any)
		if len(methods) != 1 || methods[0] != "federated" {
			t.Fatal("forged or missing authentication evidence")
		}
		roles := claims["roles"].([]any)
		found := false
		for _, role := range roles {
			if role == "app/verified" {
				found = true
			}
		}
		if !found {
			t.Fatal("provider bypassed configured transforms")
		}
	}
	client := browser()
	resp, body := fetch(client, server.URL+"/tenant/auth/login", false, "")
	if resp.StatusCode != 200 || !strings.Contains(body, "provider/application") {
		t.Fatal("provider login option missing")
	}
	post, err := http.NewRequestWithContext(t.Context(), http.MethodPost, active.Load().CallbackURL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	rejected.Body.Close()
	if rejected.StatusCode != 405 || rejected.Header.Get("Allow") != "GET" || rejected.Header.Get("Authorization") != "" {
		t.Fatal("provider method boundary")
	}
	authorization := begin(client)
	if resp, _ := fetch(client, authorization, false, ""); resp.StatusCode != 401 {
		t.Fatal("anonymous issuer accepted")
	}
	callback := issue(client, authorization)
	// A failed reload cannot consume or replace a live browser-bound ticket.
	for _, change := range []func(*tickets.Config){
		func(c *tickets.Config) { c.PublicOrigin = "https://portal.example.test:0" },
		func(c *tickets.Config) { c.IssuerURL = "https://issuer.example.test:65536/login" },
	} {
		candidate := restored
		change(&candidate)
		if got, err := tickets.New(t.Context(), &candidate); got != nil || err == nil {
			if got != nil {
				got.Close()
			}
			t.Fatal("invalid ticket reload constructed a provider")
		}
	}
	callbackURL, _ := url.Parse(callback)
	savedBinding := client.Jar.Cookies(callbackURL)
	if resp, _ := fetch(browser(), callback, false, ""); resp.StatusCode != 401 || resp.Header.Get("Authorization") != "" {
		t.Fatal("wrong browser authenticated")
	}
	if resp, _ := fetch(client, callback, false, "attacker.example.test"); resp.StatusCode != 401 || resp.Header.Get("Authorization") != "" {
		t.Fatal("wrong host authenticated")
	}
	if resp, _ := fetch(client, callback+"&format=json", false, ""); resp.StatusCode != 401 || resp.Header.Get("Authorization") != "" {
		t.Fatal("JSON negotiation bypassed strict callback validation")
	}
	// Issued ticket and browser binding survive a compatible provider/portal restart.
	if err := active.Load().Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := tickets.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(replacement)
	install(false)
	resp, _ = fetch(client, callback, false, "")
	verify(resp)
	client.Jar.SetCookies(callbackURL, savedBinding)
	if resp, _ := fetch(client, callback, false, ""); resp.StatusCode != 401 || resp.Header.Get("Authorization") != "" {
		t.Fatal("ticket replay minted token")
	}
	logout, _ := fetch(client, server.URL+"/tenant/auth/logout", false, "")
	if logout.StatusCode != 302 && logout.StatusCode != 303 {
		t.Fatal("provider portal logout", logout.StatusCode)
	}
	portalURL, _ := url.Parse(server.URL + "/tenant/auth/portal")
	for _, cookie := range client.Jar.Cookies(portalURL) {
		if cookie.Name == "AUTHP_ACCESS_TOKEN" {
			t.Fatal("logout retained access cookie")
		}
	}
	// Local factors are unavailable through ticket federation. The ticket is spent
	// even when later portal policy withholds issuance; a fresh login is required.
	install(true)
	strongClient := browser()
	strongCallback := issue(strongClient, begin(strongClient))
	strongURL, _ := url.Parse(strongCallback)
	strongBinding := strongClient.Jar.Cookies(strongURL)
	if resp, _ := fetch(strongClient, strongCallback, false, ""); resp.StatusCode != 403 || resp.Header.Get("Authorization") != "" {
		t.Fatal("ticket bypassed MFA policy", resp.StatusCode)
	}
	install(false)
	strongClient.Jar.SetCookies(strongURL, strongBinding)
	if resp, _ := fetch(strongClient, strongCallback, false, ""); resp.StatusCode != 401 || resp.Header.Get("Authorization") != "" {
		t.Fatal("policy rejection restored spent ticket")
	}
	// A backend outage cannot publish a redirect or a token.
	if err := active.Load().Close(); err != nil {
		t.Fatal(err)
	}
	if resp, _ := fetch(browser(), active.Load().CallbackURL(), false, ""); resp.StatusCode != 401 || resp.Header.Get("Location") != "" || resp.Header.Get("Authorization") != "" {
		t.Fatal("closed backend authenticated or redirected")
	}
}
