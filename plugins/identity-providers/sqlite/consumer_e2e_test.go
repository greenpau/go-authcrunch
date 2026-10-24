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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"
)

// Two portals and their trusted issuer share a file through independent handles.
// Racing the same browser evidence must publish one ticket and one signed login.
func TestE2ESQLiteTicketConcurrentPortal(t *testing.T) {
	const signingKey = "synthetic-concurrent-ticket-signing-key-0123456789"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var providers [2]*tickets.Provider
	var portals [2]*authn.Portal
	handle := func(r *http.Request) int {
		if r.Header.Get("X-Test-Ticket-Handle") == "peer" {
			return 1
		}
		return 0
	}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "alice" || password != "synthetic-issuer-password" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p := providers[handle(r)]
		q := r.URL.Query()
		if r.URL.Path != "/login" || q.Get("callback") != p.CallbackURL() {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ticket, err := p.Issue(r.Context(), q.Get("request"), &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}})
		if err != nil {
			http.Error(w, "issuance denied", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, p.CallbackURL()+"?"+url.Values{"state": {q.Get("request")}, "ticket": {ticket}}.Encode(), http.StatusSeeOther)
	}))
	defer issuer.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portals[handle(r)].ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	cfg, err := parser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm application", fmt.Sprintf("path %q", filepath.Join(dir, "tickets.db")), "public_origin " + server.URL, "issuer_url " + issuer.URL + "/login"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range providers {
		providers[i], err = tickets.New(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer providers[i].Close()
		portals[i], err = authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "concurrent-tickets", IdentityProviders: []string{"tickets"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + signingKey}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{providers[i]}})
		if err != nil {
			t.Fatal(err)
		}
		defer portals[i].Close()
	}
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	begin, err := client.Get(providers[0].CallbackURL())
	if err != nil {
		t.Fatal("begin request failed")
	}
	begin.Body.Close()
	if begin.StatusCode != http.StatusFound {
		t.Fatal("begin", begin.StatusCode)
	}
	var binding *http.Cookie
	for _, cookie := range begin.Cookies() {
		if cookie.Name == providers[0].GetLoginCookieName() {
			binding = cookie
		}
	}
	if binding == nil {
		t.Fatal("begin omitted browser binding")
	}
	race := func(target string, authenticate bool) []*http.Response {
		t.Helper()
		responses := make([]*http.Response, 2)
		failures := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range responses {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if err != nil {
				t.Fatal("prepare concurrent request failed")
			}
			if i == 1 {
				req.Header.Set("X-Test-Ticket-Handle", "peer")
			}
			if authenticate {
				req.SetBasicAuth("alice", "synthetic-issuer-password")
			} else {
				req.AddCookie(binding)
			}
			wg.Go(func() {
				<-start
				responses[i], failures[i] = client.Do(req)
				if responses[i] != nil {
					responses[i].Body.Close()
				}
			})
		}
		close(start)
		wg.Wait()
		for _, err := range failures {
			if err != nil {
				t.Fatal("concurrent request failed")
			}
		}
		return responses
	}
	callback := ""
	for _, resp := range race(begin.Header.Get("Location"), true) {
		switch resp.StatusCode {
		case http.StatusSeeOther:
			if callback != "" {
				t.Fatal("concurrent issuer published two tickets", resp.StatusCode)
			}
			callback = resp.Header.Get("Location")
		case http.StatusUnauthorized:
			if resp.Header.Get("Location") != "" {
				t.Fatal("losing issuer published a redirect", resp.StatusCode)
			}
		default:
			t.Fatal("concurrent issuer", resp.StatusCode)
		}
	}
	if callback == "" {
		t.Fatal("concurrent issuer published no ticket")
	}
	winners := 0
	for _, resp := range race(callback, false) {
		if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get("Authorization") == "" {
			for _, cookie := range resp.Cookies() {
				// The portal also tracks unauthenticated browsers with a session ID.
				if cookie.Name != "AUTHP_SESSION_ID" && cookie.Value != "" && cookie.MaxAge >= 0 {
					t.Fatal("losing callback published credentials", resp.StatusCode)
				}
			}
			continue
		}
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatal("concurrent callback", resp.StatusCode)
		}
		token, err := jwt.Parse(strings.TrimPrefix(resp.Header.Get("Authorization"), "Bearer "), func(*jwt.Token) (any, error) { return []byte(signingKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
		if err != nil || !token.Valid {
			t.Fatal("concurrent callback returned an invalid JWT")
		}
		claims := token.Claims.(jwt.MapClaims)
		if claims["sub"] != "alice" || claims["origin"] != "application" || claims["id"] == nil || claims["id"] == "" {
			t.Fatal("concurrent callback authenticated the wrong identity")
		}
		winners++
	}
	if winners != 1 {
		t.Fatal("concurrent callbacks did not publish exactly one login")
	}
	for _, resp := range race(callback, false) {
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatal("callback replay authenticated", resp.StatusCode)
		}
	}
	for _, p := range providers {
		if !p.Configured() {
			t.Fatal("concurrent login quarantined a healthy provider")
		}
	}
}

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
	cfg, err := parser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm application", fmt.Sprintf("path %q", filepath.Join(dir, "tickets.db")), "public_origin " + server.URL, "base_path /tenant/auth", "issuer_url " + issuer.URL + "/login", "timeout 750ms", "cookie_name APP_TICKET_BINDING", "attach to local identity store accounts"})
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
	accountPath := filepath.Join(dir, "accounts.json")
	localStore, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "accounts", Kind: "local", Params: map[string]any{"path": accountPath, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := localStore.Configure(); err != nil {
		t.Fatal(err)
	}
	install := func(requireMFA bool) {
		t.Helper()
		actions := []string{"add role app/verified"}
		if requireMFA {
			actions = append(actions, "require totp")
		}
		p, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "ticket-portal", IdentityProviders: []string{"tickets"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + secret}, UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"exact match realm application"}, Actions: actions}}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{active.Load()}, IdentityStores: []ids.IdentityStore{localStore}})
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
		if claims["id"] == nil || claims["id"] == "" || claims["id"] == "alice" || claims["sub"] != "alice" || claims["origin"] != "application" || claims["email"] != "alice@example.test" {
			t.Fatal("wrong provider identity")
		}
		accounts, err := identity.NewDatabase(accountPath)
		if err != nil {
			t.Fatal(err)
		}
		foundAccount := false
		for _, u := range accounts.Users {
			if u.ID == claims["id"] {
				foundAccount = len(u.ExternalAccounts) == 1 && u.ExternalAccounts[0].Provider == "tickets"
			}
		}
		if !foundAccount {
			t.Fatal("ticket identity was not written to its configured attachment")
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

// A login page that carries its tab's destination still starts a ticket login:
// the provider link has no query, which the ticket protocol rejects, and the
// completed login returns through the portal's redirect cookie to that page.
func TestE2ESQLiteTicketPortalLoginPageDestination(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var active atomic.Pointer[tickets.Provider]
	var portal atomic.Pointer[authn.Portal]
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := active.Load()
		q := r.URL.Query()
		ticket, err := p.Issue(r.Context(), q.Get("request"), &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}})
		if r.URL.Path != "/login" || q.Get("callback") != p.CallbackURL() || err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		http.Redirect(w, r, p.CallbackURL()+"?"+url.Values{"state": {q.Get("request")}, "ticket": {ticket}}.Encode(), 303)
	}))
	defer issuer.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.Load().ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	cfg, err := parser.NewSQLiteTicketProviderConfigFromDirectives([]string{"name tickets", "realm application", fmt.Sprintf("path %q", filepath.Join(dir, "tickets.db")), "public_origin " + server.URL, "base_path /auth", "issuer_url " + issuer.URL + "/login", "cookie_name APP_TICKET_BINDING"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := tickets.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(provider)
	defer provider.Close()
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.test", "prefix", "/")
	if err != nil {
		t.Fatal(err)
	}
	p, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "ticket-destination", IdentityProviders: []string{"tickets"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify synthetic-ticket-destination-key-0123456789"}, TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{provider}})
	if err != nil {
		t.Fatal(err)
	}
	portal.Store(p)
	defer p.Close()

	client := *server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Jar, err = cookiejar.New(nil); err != nil {
		t.Fatal(err)
	}
	get := func(target string) (*http.Response, string) {
		t.Helper()
		resp, err := client.Get(target)
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

	destination := "https://app.example.test/tab?x=one%26two"
	login, err := url.Parse(server.URL + "/auth/login?redirect_url=" + url.QueryEscape(destination))
	if err != nil {
		t.Fatal(err)
	}
	resp, page := get(login.String())
	link := regexp.MustCompile(`<a href="(provider/application[^"]*)"`).FindStringSubmatch(page)
	if resp.StatusCode != 200 || link == nil || link[1] != "provider/application" {
		t.Fatalf("login page returned HTTP %d with ticket provider link %q", resp.StatusCode, link)
	}
	start, err := login.Parse(link[1])
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = get(start.String())
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), issuer.URL+"/login?") {
		t.Fatalf("ticket login did not start from the login page link: HTTP %d", resp.StatusCode)
	}
	resp, _ = get(resp.Header.Get("Location"))
	if resp.StatusCode != 303 {
		t.Fatalf("issuer returned HTTP %d", resp.StatusCode)
	}
	resp, _ = get(resp.Header.Get("Location"))
	if resp.StatusCode != 303 || resp.Header.Get("Authorization") == "" || resp.Header.Get("Location") != destination {
		t.Fatalf("ticket login completed with HTTP %d to %q, want %q", resp.StatusCode, resp.Header.Get("Location"), destination)
	}
}
