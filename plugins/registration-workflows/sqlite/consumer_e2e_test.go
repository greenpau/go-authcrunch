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
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	notifications "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	enrollment "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite/parser"
)

func TestE2ESQLiteRegistrationPortal(t *testing.T) {
	const password = "Synthetic-registration-password-2026!"
	const signingKey = "synthetic-registration-signing-secret-0123456789"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), &accounts.Config{Name: "accounts", Realm: "staff", Path: filepath.Join(dir, "accounts.db"), Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	out, err := notifications.New(t.Context(), &notifications.Config{Name: "mail", Path: filepath.Join(dir, "outbox.db"), Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	var current atomic.Pointer[authn.Portal]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := current.Load().ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	cfg, err := parser.NewSQLiteRegistrationConfigFromDirectives([]string{"name enrollment", fmt.Sprintf("path %q", filepath.Join(dir, "registration.db")), "identity_store accounts", "realm staff", "email_provider mail", "public_origin " + server.URL, "base_path /tenant/auth", "timeout 5s"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored enrollment.Config
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	// An installed version-1 workflow must upgrade without manual file replacement.
	legacy, err := sql.Open("sqlite", restored.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"PRAGMA application_id=1094931287", "PRAGMA user_version=1", "CREATE TABLE registrations (id BLOB PRIMARY KEY, binding BLOB NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, enrollment TEXT NOT NULL, password BLOB, code BLOB, expires INTEGER NOT NULL, attempts INTEGER NOT NULL, state TEXT NOT NULL)"} {
		if _, err := legacy.ExecContext(t.Context(), statement); err != nil {
			legacy.Close()
			t.Fatal(err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(restored.Path, 0600); err != nil {
		t.Fatal(err)
	}
	workflow, err := enrollment.New(t.Context(), &restored, store, out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		workflow.Close()
		if p := current.Load(); p != nil {
			p.Close()
		}
	}()
	destination := "https://trusted.example.test/registered?x=one%26two"
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", "trusted.example.test", "prefix", "/")
	if err != nil {
		t.Fatal(err)
	}
	install := func() {
		t.Helper()
		p, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "registration", TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted}, IdentityStores: []string{"accounts"}, UserRegistries: []string{"enrollment"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + signingKey}}, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.AddUserRegistry(workflow); err != nil {
			p.Close()
			t.Fatal(err)
		}
		old := current.Swap(p)
		if old != nil {
			old.Close()
		}
	}
	install()
	for _, change := range []func(*enrollment.Config){
		func(c *enrollment.Config) { c.BasePath = "/api/auth" },
		func(c *enrollment.Config) { c.PublicOrigin = "https://portal.example.test:65536" },
	} {
		candidate := restored
		change(&candidate)
		if got, err := enrollment.New(t.Context(), &candidate, store, out); err == nil || got != nil {
			if got != nil {
				got.Close()
			}
			t.Fatal("invalid registration reload constructed a workflow")
		}
	}
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(method, target string, form url.Values, host string) (int, string, string) {
		if strings.HasPrefix(target, "/") {
			target = server.URL + target
		}
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(t.Context(), method, target, body)
		if err != nil {
			t.Fatal(err)
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Header.Get("Location"), string(data)
	}
	if status, _, _ := request("GET", server.URL+"/tenant/auth/register/staff", nil, ""); status != 200 {
		t.Fatal("registration form", status)
	}
	if status, _, body := request("POST", server.URL+"/tenant/auth/register/staff?redirect_url="+url.QueryEscape(destination), url.Values{"registrant": {"alice"}, "registrant_password": {password}, "registrant_email": {"alice@example.test"}}, "attacker.example.test"); status != 200 {
		t.Fatal("registration submission", status, body)
	}
	if _, err := store.FetchUserData("alice", "alice@example.test"); err == nil {
		t.Fatal("account exists before email confirmation")
	}
	message, err := out.Claim(t.Context())
	if err != nil {
		t.Fatal("confirmation was not queued", err)
	}
	if len(message.Recipients) != 1 || message.Recipients[0] != "alice@example.test" {
		t.Fatal("wrong confirmation recipient")
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(message.Body)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(decoded), "attacker.example.test") || strings.Contains(string(decoded), password) {
		t.Fatal("notification leaked password or used untrusted Host")
	}
	linkMatch := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(string(decoded))
	codeMatch := regexp.MustCompile(`<code>([A-Za-z0-9]{6,8})</code>`).FindStringSubmatch(string(decoded))
	if len(linkMatch) != 2 || len(codeMatch) != 2 {
		t.Fatal("confirmation mail lacks link or code", string(decoded))
	}
	link, code := linkMatch[1], codeMatch[1]
	if !strings.HasPrefix(link, server.URL+"/tenant/auth/register/staff/ack/") {
		t.Fatal("noncanonical confirmation URL", link)
	}
	if err := out.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
		t.Fatal(err)
	}
	id := link[strings.LastIndex(link, "/")+1:]
	public, err := workflow.GetRegistrationEntry(id)
	if err != nil || public["password"] != "" || public["registration_code"] != "" {
		t.Fatal("unsafe pending entry", err)
	}
	// Pending state survives a workflow and portal restart at the same public origin.
	if err := workflow.Close(); err != nil {
		t.Fatal(err)
	}
	workflow, err = enrollment.New(t.Context(), &restored, store, out)
	if err != nil {
		t.Fatal(err)
	}
	install()
	if status, _, _ := request("GET", link, nil, ""); status != 200 {
		t.Fatal("confirmation page", status)
	}
	for _, candidate := range []struct {
		target string
		values url.Values
	}{
		{link, url.Values{"registration_code": {"wrong"}}},
		{link, url.Values{"registration_code": {code, code}}},
		{link + "?registration_code=" + code, url.Values{"unused": {"value"}}},
	} {
		status, _, body := request("POST", candidate.target, candidate.values, "")
		if status != 200 || !strings.Contains(body, "Registration confirmation denied") {
			t.Fatal("invalid confirmation accepted", status, body)
		}
	}
	if _, err := store.FetchUserData("alice", "alice@example.test"); err == nil {
		t.Fatal("invalid confirmation created account")
	}
	// A real competing reader makes the pending COMMIT fail after account
	// creation. HTTP must withhold success; fresh handles reconcile the same ID.
	competing, err := sql.Open("sqlite", restored.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer competing.Close()
	readTx, err := competing.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	var pendingCount int
	if err := readTx.QueryRowContext(t.Context(), "SELECT count(*) FROM registrations").Scan(&pendingCount); err != nil {
		t.Fatal(err)
	}
	if status, location, body := request("POST", link, url.Values{"registration_code": {code}}, ""); status != 200 || location != "" || !strings.Contains(body, "Registration confirmation denied") {
		t.Fatal("uncertain commit published HTTP success", status)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := competing.Close(); err != nil {
		t.Fatal(err)
	}
	created, err := store.FetchUserData("alice", "alice@example.test")
	if err != nil {
		t.Fatal("fixture did not commit the account first", err)
	}
	if err := workflow.Close(); err != nil {
		t.Fatal(err)
	}
	workflow, err = enrollment.New(t.Context(), &restored, store, out)
	if err != nil {
		t.Fatal(err)
	}
	install()
	loginLocation := ""
	if status, location, body := request("POST", link+"?redirect_url=https%3A%2F%2Ftrusted.example.test%2Freplaced", url.Values{"registration_code": {code}}, ""); status != 303 || location != server.URL+"/tenant/auth/login?redirect_url="+url.QueryEscape(destination) {
		t.Fatal("confirmation did not activate login", status, location, body)
	} else {
		loginLocation = strings.TrimPrefix(location, server.URL)
	}
	reconciled, err := store.FetchUserData("alice", "alice@example.test")
	if err != nil || created["id"] != reconciled["id"] {
		t.Fatal("recovery replaced account identity", err)
	}
	if status, _, body := request("POST", link, url.Values{"registration_code": {code}}, ""); status != 200 || !strings.Contains(body, "Registration confirmation denied") {
		t.Fatal("confirmation replay accepted", status, body)
	}

	// Submit the rendered form, not a handcrafted destination at completion.
	if status, _, page := request("GET", server.URL+loginLocation, nil, ""); status != 200 {
		t.Fatal("login page", status)
	} else {
		action := regexp.MustCompile(`<form[^>]*action="([^"]+)"`).FindStringSubmatch(page)
		if len(action) != 2 {
			t.Fatal("login form absent")
		}
		formURL := html.UnescapeString(action[1])
		if !strings.HasPrefix(formURL, "/") {
			t.Fatal("invalid login form")
		}
		status, sandbox, _ := request("POST", server.URL+formURL, url.Values{"username": {"alice"}, "realm": {"staff"}}, "")
		if status != 303 {
			t.Fatal("login start", status)
		}
		if status, _, _ := request("POST", sandbox, url.Values{"secret": {password}}, ""); status != 303 {
			t.Fatal("password", status)
		}
		if status, location, _ := request("GET", sandbox, nil, ""); status != 303 || location != destination {
			t.Fatal("registration destination lost at login", status, location)
		}
	}
	client.Jar = nil // Later registration attempts use an anonymous consumer again.
	native, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL + "/tenant/auth", Realm: "staff", Username: "alice", Password: password}, authclient.Options{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	result, err := native.Authenticate(t.Context())
	if err != nil {
		t.Fatal("confirmed account cannot log in", err)
	}
	token, err := jwt.Parse(result.AccessToken, func(*jwt.Token) (any, error) { return []byte(signingKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
	if err != nil || !token.Valid {
		t.Fatal("invalid JWT", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "alice" || claims["origin"] != "staff" {
		t.Fatal("wrong identity")
	}
	roles := claims["roles"].([]any)
	if len(roles) != 1 || roles[0] != "authp/user" {
		t.Fatal("registration granted unexpected role")
	}

	t.Run("expiry while account database is locked", func(t *testing.T) {
		if status, _, _ := request("POST", server.URL+"/tenant/auth/register/staff", url.Values{"registrant": {"eve"}, "registrant_password": {password}, "registrant_email": {"eve@example.test"}}, ""); status != 200 {
			t.Fatal("submission", status)
		}
		message, err := out.Claim(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(message.Body)))
		if err != nil {
			t.Fatal(err)
		}
		links := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(string(decoded))
		codes := regexp.MustCompile(`<code>([A-Za-z0-9]{6,8})</code>`).FindStringSubmatch(string(decoded))
		if len(links) != 2 || len(codes) != 2 {
			t.Fatal("missing confirmation")
		}
		pending, err := sql.Open("sqlite", restored.Path)
		if err != nil {
			t.Fatal(err)
		}
		defer pending.Close()
		deadline := time.Now().Truncate(time.Second).Add(3 * time.Second)
		if _, err := pending.ExecContext(t.Context(), "UPDATE registrations SET expires=? WHERE username=?", deadline.Unix(), "eve"); err != nil {
			t.Fatal(err)
		}
		blocker, err := sql.Open("sqlite", filepath.Join(dir, "accounts.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Close()
		conn, err := blocker.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		defer conn.ExecContext(context.Background(), "ROLLBACK")
		released := make(chan error, 1)
		timer := time.AfterFunc(time.Until(deadline)+100*time.Millisecond, func() {
			_, err := conn.ExecContext(t.Context(), "ROLLBACK")
			released <- err
		})
		defer timer.Stop()
		status, location, body := request("POST", links[1], url.Values{"registration_code": {codes[1]}}, "")
		if err := <-released; err != nil {
			t.Fatal(err)
		}
		if status != 200 || location != "" || !strings.Contains(body, "Registration confirmation denied") {
			t.Fatal("expired confirmation accepted", status)
		}
		if _, err := store.FetchUserData("eve", "eve@example.test"); err == nil {
			t.Fatal("expired confirmation created account")
		}
		if err := out.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
			t.Fatal(err)
		}
	})
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	status, _, body := request("POST", server.URL+"/tenant/auth/register/staff", url.Values{"registrant": {"bob"}, "registrant_password": {password}, "registrant_email": {"bob@example.test"}}, "")
	if status != 200 || !strings.Contains(body, "Internal registration messaging error") {
		t.Fatal("unexpected messaging failure response", status)
	}
	if _, err := store.FetchUserData("bob", "bob@example.test"); err == nil {
		t.Fatal("failed notification created account")
	}
	if err := store.DeleteUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := workflow.ConfirmRegistration(t.Context(), id, code); err == nil {
		t.Fatal("spent confirmation recreated deleted account")
	}
}
