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

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp"
)

func testProvider(t *testing.T) (*Provider, *Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := &Config{Name: "tickets", Realm: "application", Path: filepath.Join(dir, "tickets.db"), PublicOrigin: "https://portal.example.test", IssuerURL: "https://issuer.example.test/login", Timeout: "5s"}
	p, err := New(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, c
}
func ticketIdentity() *idp.LoginIdentity {
	return &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}
}
func beginTicket(t *testing.T, p *Provider) (string, *http.Cookie) {
	t.Helper()
	result, err := p.Login(t.Context(), httptest.NewRequest("GET", p.CallbackURL(), nil))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "issuer.example.test" || u.Query().Get("callback") != p.CallbackURL() || result.Identity != nil {
		t.Fatal("unpinned redirect")
	}
	return u.Query().Get("request"), result.Cookie
}
func callback(p *Provider, state, ticket string, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", p.CallbackURL()+"?"+url.Values{"state": {state}, "ticket": {ticket}}.Encode(), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}
func TestTicketsSingleUseRestartAndSnapshots(t *testing.T) {
	p, config := testProvider(t)
	if config.BasePath != "" {
		t.Fatal("mutated caller config")
	}
	state, cookie := beginTicket(t, p)
	if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/auth/provider/application" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
		t.Fatal("unsafe binding cookie")
	}
	identity := ticketIdentity()
	ticket, err := p.Issue(t.Context(), state, identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.Subject = "attacker"
	identity.Roles[0] = "authp/admin"
	if _, err := p.Issue(t.Context(), state, ticketIdentity()); !errors.Is(err, ErrDenied) {
		t.Fatal("duplicate issue", err)
	}
	if err := p.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		var request, browser, secret []byte
		if err := tx.QueryRowContext(ctx, "SELECT request,browser,ticket FROM tickets").Scan(&request, &browser, &secret); err != nil {
			return err
		}
		if string(request) == state || string(browser) == cookie.Value || string(secret) == ticket || len(request) != 32 || len(browser) != 32 || len(secret) != 32 {
			t.Fatal("raw credential persistence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	result, err := fresh.Login(t.Context(), callback(fresh, state, ticket, cookie))
	if err != nil {
		t.Fatal(err)
	}
	if result.Identity.Subject != "alice" || result.Identity.Roles[0] != "authp/user" || result.Cookie.MaxAge != -1 || result.Cookie.Value != "" {
		t.Fatal("identity snapshot or cookie deletion")
	}
	if replay, err := fresh.Login(t.Context(), callback(fresh, state, ticket, cookie)); replay != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("replay accepted", err)
	}
	encoded, _ := json.Marshal(result)
	if string(encoded) != "{}" {
		t.Fatal("runtime result serialized")
	}
}
func TestTicketsRejectUnboundCallbacks(t *testing.T) {
	p, c := testProvider(t)
	state, cookie := beginTicket(t, p)
	ticket, err := p.Issue(t.Context(), state, ticketIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = "POST" }, func(r *http.Request) { r.TLS = nil }, func(r *http.Request) { r.Host = "attacker.example.test" }, func(r *http.Request) { r.URL.Path += "/extra" }, func(r *http.Request) { r.URL.RawPath = "/auth/provider/%61pplication" }, func(r *http.Request) { r.Header.Del("Cookie") }, func(r *http.Request) { r.AddCookie(cookie) }, func(r *http.Request) { r.Header.Set("Cookie", cookie.Name+"="+secret()) }, func(r *http.Request) { r.URL.RawQuery += "&state=" + state }, func(r *http.Request) { r.URL.RawQuery += "&extra=value" }, func(r *http.Request) { r.URL.RawQuery = "state=" + state + "&ticket=" + secret() }, func(r *http.Request) { r.URL.RawQuery = "state=" + secret() + "&ticket=" + ticket }, func(r *http.Request) { r.URL.RawQuery = "state=%zz" }, func(r *http.Request) { r.URL.RawQuery = strings.Repeat("x", 1025) },
	} {
		r := callback(p, state, ticket, cookie)
		mutate(r)
		if result, err := p.Login(t.Context(), r); result != nil || err == nil {
			t.Fatal("unbound callback accepted")
		}
	}
	changed := *c
	changed.IssuerURL = "https://other.example.test/login"
	other, err := New(t.Context(), &changed)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// Even the correct browser cookie cannot cross a changed issuer binding.
	otherCookie := *cookie
	otherCookie.Name = other.cookieName
	if result, err := other.Login(t.Context(), callback(other, state, ticket, &otherCookie)); result != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("wrong issuer accepted", err)
	}
	if result, err := p.Login(t.Context(), callback(p, state, ticket, cookie)); result == nil || err != nil {
		t.Fatal("rejected callback consumed valid ticket", err)
	}
}
func TestTicketsConcurrentIssueAndConsume(t *testing.T) {
	p, config := testProvider(t)
	other, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	state, cookie := beginTicket(t, p)
	start := make(chan struct{})
	var wg sync.WaitGroup
	tickets := make(chan string, 2)
	failures := make(chan error, 2)
	for _, instance := range []*Provider{p, other} {
		wg.Go(func() {
			<-start
			ticket, err := instance.Issue(t.Context(), state, ticketIdentity())
			tickets <- ticket
			failures <- err
		})
	}
	close(start)
	wg.Wait()
	close(tickets)
	close(failures)
	ticket := ""
	for candidate := range tickets {
		if candidate != "" {
			if ticket != "" {
				t.Fatal("double issuance")
			}
			ticket = candidate
		}
	}
	if ticket == "" {
		t.Fatal("no ticket")
	}
	denied := 0
	for err := range failures {
		if errors.Is(err, ErrDenied) {
			denied++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if denied != 1 {
		t.Fatal("missing losing issuer")
	}
	results := make(chan *idp.HTTPLoginResult, 2)
	failures = make(chan error, 2)
	start = make(chan struct{})
	for _, instance := range []*Provider{p, other} {
		wg.Go(func() {
			<-start
			result, err := instance.Login(t.Context(), callback(instance, state, ticket, cookie))
			results <- result
			failures <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	successes := 0
	for result := range results {
		if result != nil {
			successes++
		}
	}
	denied = 0
	for err := range failures {
		if errors.Is(err, ErrDenied) {
			denied++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if successes != 1 || denied != 1 {
		t.Fatal("ticket not consumed exactly once")
	}
}
func TestTicketsExpiryCapacityAndFailures(t *testing.T) {
	p, _ := testProvider(t)
	state, cookie := beginTicket(t, p)
	if result, err := p.Login(t.Context(), callback(p, state, secret(), cookie)); result != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("unissued ticket accepted", err)
	}
	ticket, err := p.Issue(t.Context(), state, ticketIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE tickets SET ticket_expires=1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := p.Login(t.Context(), callback(p, state, ticket, cookie)); result != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("expired ticket accepted", err)
	}
	if err := p.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE tickets SET expires=1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Issue(t.Context(), state, ticketIdentity()); !errors.Is(err, ErrDenied) {
		t.Fatal("expired request issued", err)
	}
	beginTicket(t, p) // Prunes expired requests before admission.
	if err := p.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO tickets SELECT CAST(printf('%064d',n.x) AS BLOB),binding,browser,expires,ticket,ticket_expires,identity FROM tickets CROSS JOIN (WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1023) SELECT x FROM n) n")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := p.Login(t.Context(), httptest.NewRequest("GET", p.CallbackURL(), nil)); result != nil || !errors.Is(err, ErrFull) {
		t.Fatal("capacity admission", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := p.Login(ctx, httptest.NewRequest("GET", p.CallbackURL(), nil)); result != nil || err == nil {
		t.Fatal("canceled request accepted")
	}
	if ticket, err := p.Issue(t.Context(), "bad", ticketIdentity()); ticket != "" || err == nil {
		t.Fatal("bad state accepted")
	}
	if ticket, err := p.Issue(t.Context(), secret(), nil); ticket != "" || err == nil {
		t.Fatal("nil identity accepted")
	}
	if !p.Configured() || p.Configure() != nil || p.GetKind() != "sqlite-ticket" || p.GetDriver() != "ticket" || p.GetName() != "tickets" || p.GetRealm() != "application" || p.GetLogoutURL() != "" || p.GetIdentityTokenCookieName() != "" || p.Request(0, nil) == nil {
		t.Fatal("provider metadata contract")
	}
	metadata := p.GetConfig()
	if len(metadata) != 3 {
		t.Fatal("unsafe metadata")
	}
	metadata["name"] = "bad"
	if p.GetConfig()["name"] != "tickets" {
		t.Fatal("aliased metadata")
	}
	icon := p.GetLoginIcon()
	icon.Endpoint = "bad"
	if p.GetLoginIcon().Endpoint != "provider/application" {
		t.Fatal("icon alias")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if p.Configured() || p.Configure() == nil {
		t.Fatal("closed provider configured")
	}
	if result, err := p.Login(t.Context(), httptest.NewRequest("GET", p.CallbackURL(), nil)); result != nil || err == nil {
		t.Fatal("closed login accepted")
	}
	if got, err := New(t.Context(), nil); got != nil || err == nil {
		t.Fatal("nil config accepted")
	}
}
func TestTicketsUncertainConsumptionWithholdsIdentity(t *testing.T) {
	p, config := testProvider(t)
	state, cookie := beginTicket(t, p)
	ticket, err := p.Issue(t.Context(), state, ticketIdentity())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- reader.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM tickets").Scan(&count); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	result, err := p.Login(t.Context(), callback(p, state, ticket, cookie))
	close(release)
	if readErr := <-done; readErr != nil {
		t.Fatal(readErr)
	}
	if result != nil || !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain consume published identity", err)
	}
	if p.Configured() {
		t.Fatal("uncertain handle stayed active")
	}
}

func TestTicketsTypedConfig(t *testing.T) {
	p, config := testProvider(t)
	if config.CookieName != "" || config.BasePath != "" {
		t.Fatal("constructor mutated defaults")
	}
	config.Name = "changed"
	if p.GetName() != "tickets" {
		t.Fatal("configuration alias")
	}
	for _, change := range []func(*Config){func(c *Config) { c.Name = "" }, func(c *Config) { c.Realm = "../realm" }, func(c *Config) { c.Path = "relative" }, func(c *Config) { c.Timeout = "31s" }, func(c *Config) { c.PublicOrigin = "https://portal.example.test/" }, func(c *Config) { c.IssuerURL = "http://issuer.example.test/login" }, func(c *Config) { c.BasePath = "/provider" }, func(c *Config) { c.CookieName = "__Host-BINDING" }, func(c *Config) { c.CookieName = "bad\nname" }} {
		c := *config
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid typed configuration accepted")
		}
	}
	if (*Config)(nil).Validate() == nil {
		t.Fatal("nil config accepted")
	}
}
