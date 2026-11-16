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
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	"go.uber.org/zap"
)

func sqlitePortalRequest(t *testing.T, f *documentsE2E, token, method, path string, body any, want int) map[string]any {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+strings.TrimSuffix(f.base, "/")+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.server.URL)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatal("portal request failed", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != want {
		t.Fatalf("%s %s HTTP %d want %d", method, path, res.StatusCode, want)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("invalid portal response", path)
	}
	openAPIJourneyResponse(t, f.server.URL+strings.TrimSuffix(f.base, "/"), req.URL, method, res.StatusCode, res.Header, raw)
	return out
}

func TestE2ESQLiteProfileAndAdministration(t *testing.T) {
	f, cfg := newSQLiteDocumentsE2E(t, "/auth")
	alice, bob, admin := f.login(t, "alice"), f.login(t, "bob"), f.login(t, "charlie")
	request := func(token, kind string, extra map[string]any, want int) map[string]any {
		t.Helper()
		if extra == nil {
			extra = map[string]any{}
		}
		extra["kind"] = kind
		return sqlitePortalRequest(t, f, token, "POST", "/api/profile", extra, want)
	}
	caps := sqlitePortalRequest(t, f, alice, "GET", "/api/capabilities", nil, 200)
	if caps["backend"].(map[string]any)["kind"] != "sqlite" || caps["profile"].(map[string]any)["reason"] != "available" || caps["admin"].(map[string]any)["reason"] != "forbidden" || caps["oidc"].(map[string]any)["reason"] != "disabled" {
		t.Fatal("incorrect capability state")
	}
	storeCaps := caps["store"].(map[string]any)
	for _, key := range []string{"api_keys", "public_keys", "mfa", "authentication_flows", "connections"} {
		if storeCaps[key] != false {
			t.Fatal("advertised unsupported capability", key)
		}
	}
	info := request(alice, "fetch_user_info", map[string]any{"username": "bob", "email": "bob@example.test"}, 200)
	entry := info["entry"].(map[string]any)
	metadata := entry["metadata"].(map[string]any)
	if metadata["username"] != "alice" || metadata["email"] != "alice@example.test" {
		t.Fatal("claims or body selected another account")
	}
	aliceID := metadata["id"].(string)
	dashboard := request(alice, "fetch_user_dashboard_data", nil, 200)["entry"].(map[string]any)
	if len(dashboard["asset_count"].(map[string]any)) != 0 || dashboard["connected_accounts"] != nil {
		t.Fatal("unsupported collection reported empty")
	}
	request(alice, "fetch_debug", nil, 200)
	for _, kind := range []string{"fetch_user_api_keys", "add_user_api_key", "fetch_user_ssh_keys", "fetch_user_gpg_keys", "fetch_user_multi_factor_authenticators", "fetch_user_auth_challenges", "overwrite_user_auth_challenges", "fetch_user_u2f_reg_params"} {
		if request(alice, kind, nil, 501)["code"] != "unsupported_capability" {
			t.Fatal("unstable unsupported error")
		}
	}
	// Safe structured DTOs are compatible with the established role/name/email models.
	selector := map[string]any{"realm": "local", "operation": "info", "user": map[string]any{"username": "alice", "email": "alice@example.test"}}
	sqlitePortalRequest(t, f, bob, "POST", "/api/server/user", selector, 403)
	record := sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", selector, 200)
	if record["id"] != aliceID || record["email_address"].(map[string]any)["address"] != "alice@example.test" || record["roles"].([]any)[0].(map[string]any)["organization"] != "authp" {
		t.Fatal("admin DTO mismatch")
	}
	if record["passwords"] != nil || record["mfa_tokens"] != nil {
		t.Fatal("SQLite admin exposed verifier collections")
	}
	selector["operation"] = "overwrite_auth_challenges"
	if sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", selector, 501)["code"] != "unsupported_capability" {
		t.Fatal("unsupported admin operation not explicit")
	}
	selector["operation"] = "add_roles"
	oversizedRoles := make([]string, 12)
	for i := range oversizedRoles {
		oversizedRoles[i] = strings.Repeat("<", 126) + fmt.Sprintf("%02d", i)
	}
	selector["user"].(map[string]any)["roles"] = oversizedRoles
	for _, operation := range []string{"add_roles", "overwrite_roles"} {
		selector["operation"] = operation
		result := sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", selector, 200)
		if result["status"] != "failure" || result["code"] != "operation_failed" {
			t.Fatalf("%s accepted unreadable role encoding", operation)
		}
		// The exact old login still works: rejection changed neither the record
		// nor the generation, including when the input was a valid string array.
		request(alice, "fetch_user_info", nil, 200)
	}
	selector["operation"] = "add_roles"
	selector["user"].(map[string]any)["roles"] = []string{"extra"}
	if sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", selector, 200)["status"] != "success" {
		t.Fatal("atomic role addition failed")
	}
	request(alice, "fetch_user_info", nil, 401)
	sqlitePortalRequest(t, f, alice, "GET", "/api/capabilities", nil, 401)
	alice = f.login(t, "alice")
	request(alice, "update_user_password", map[string]any{"old_password": tests.TestPwd1, "new_password": "bcrypt:10:reserved-import"}, 400)
	request(alice, "fetch_user_info", nil, 200)
	key := f.enroll(t, alice)
	request(alice, "update_user_password", map[string]any{"old_password": tests.TestPwd1, "new_password": "  Replacement-password-2026!  "}, 200)
	request(alice, "fetch_user_info", nil, 401)
	f.message(t, alice, "bootstrap", nil, 401)
	// Reopening preserves the record and password but never accepts the old epoch.
	management, err := accounts.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	for secret, want := range map[string]bool{tests.TestPwd1: false, "  Replacement-password-2026!  ": true} {
		r := &requests.Request{User: requests.User{Username: "alice", Password: secret}}
		err := management.Request(operator.Authenticate, r)
		if (err == nil) != want {
			t.Fatal("password persistence mismatch")
		}
		if want && r.Authentication.UserID != key.UserID {
			t.Fatal("password change changed vault owner")
		}
	}
	request(bob, "fetch_user_info", nil, 200)
	selector["operation"] = "disable"
	selector["user"].(map[string]any)["email"] = "wrong@example.test"
	failure := sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", selector, 200)
	if failure["status"] != "failure" || failure["code"] != "operation_failed" || failure["password"] != nil {
		t.Fatal("failed admin mutation was not a safe failure envelope")
	}
	selector["realm"] = "absent"
	sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", selector, 404)
}

func TestE2ESQLiteCapabilitiesDisabledAndUnavailable(t *testing.T) {
	f, _ := newSQLiteDocumentsE2E(t, "/tenant/xauth")
	token := f.login(t, "alice")
	sqlitePortalRequest(t, f, token, "POST", "/api/capabilities", nil, 405)
	sqlitePortalRequest(t, f, token, "GET", "/api/capabilities?unexpected=1", nil, 400)
	sqlitePortalRequest(t, f, "", "GET", "/api/capabilities", nil, 401)
	f.mu.Lock()
	f.portal.Close()
	cfg := &authn.PortalConfig{Name: "disabled-capabilities", IdentityStores: []string{f.store.GetName()}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify synthetic-sqlite-capabilities-hmac-0123456789"}, API: &authn.APIConfig{}}
	var err error
	f.portal, err = authn.NewPortal(authn.PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{f.store}})
	f.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	token = f.login(t, "alice")
	caps := sqlitePortalRequest(t, f, token, "GET", "/api/capabilities", nil, 200)
	for _, key := range []string{"profile", "admin", "documents", "oidc", "private_key_export"} {
		if caps[key].(map[string]any)["reason"] != "disabled" {
			t.Fatal("disabled feature advertised", key)
		}
	}
	if caps["jwks"].(map[string]any)["reason"] != "no_eligible_keys" {
		t.Fatal("HMAC key availability misreported")
	}
	f.store.(*accounts.Store).Close()
	if sqlitePortalRequest(t, f, token, "GET", "/api/capabilities", nil, 503)["code"] != "storage_unavailable" {
		t.Fatal("outage reported as invalid proof")
	}
}

func TestE2ESQLiteProfileInvalidStoredPassword(t *testing.T) {
	f, cfg := newSQLiteDocumentsE2E(t, "/auth")
	token := f.login(t, "alice")
	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var original string
	var version uint64
	if err := db.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE realm='local' AND username='alice'").Scan(&original, &version); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"malformed":        "invalid-stored-verifier",
		"untrusted_cost":   strings.Replace(original, "$10$", "$31$", 1),
		"invalid_encoding": original[:7] + "!" + original[8:], // Cost parses, but the salt cannot be decoded.
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := db.ExecContext(t.Context(), "UPDATE accounts SET password=? WHERE realm='local' AND username='alice'", invalid); err != nil {
				t.Fatal(err)
			}
			response := sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{
				"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": "Replacement-password-2026!",
			}, http.StatusServiceUnavailable)
			if response["code"] != "storage_unavailable" || response["entry"] != nil {
				t.Fatal("stored verifier failure was not safely classified")
			}
			var hash string
			var current uint64
			if err := db.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE realm='local' AND username='alice'").Scan(&hash, &current); err != nil {
				t.Fatal(err)
			}
			if hash != invalid || current != version {
				t.Fatal("failed profile mutation changed persistent state")
			}
		})
	}
	if _, err := db.ExecContext(t.Context(), "UPDATE accounts SET password=? WHERE realm='local' AND username='alice'", original); err != nil {
		t.Fatal(err)
	}
	// Repairing the synthetic storage fault restores real password login; the
	// rejected request must not have installed its proposed replacement.
	token = f.login(t, "alice")
	sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, http.StatusOK)
}

// Retain every concrete store capability, but acquire a competing writer only
// after the portal's initial identity check. The real mutation then times out.
type contendedProfileStore struct {
	*accounts.Store
	writer  *sql.Conn
	outcome chan error
}

func (s *contendedProfileStore) RequestWithIdentity(op operator.Type, r *requests.Request) error {
	if op != operator.ChangePassword {
		return s.Store.RequestWithIdentity(op, r)
	}
	if _, err := s.writer.ExecContext(r.Upstream.Request.Context(), "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	err := s.Store.RequestWithIdentity(op, r)
	s.outcome <- err
	return err
}

func TestE2ESQLiteProfileStorageTimeout(t *testing.T) {
	f, cfg := newSQLiteDocumentsE2E(t, "/auth")
	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	writer, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	defer writer.ExecContext(context.Background(), "ROLLBACK")
	s := &contendedProfileStore{Store: f.store.(*accounts.Store), writer: writer, outcome: make(chan error, 1)}
	f.mu.Lock()
	f.portal.Close()
	f.store = s
	f.portal = f.newPortal()
	f.mu.Unlock()
	alice, admin := f.login(t, "alice"), f.login(t, "charlie")
	var original string
	var version uint64
	if err := writer.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE username='alice'").Scan(&original, &version); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"admission", "password", "admin"} {
		t.Run(operation, func(t *testing.T) {
			if operation != "password" {
				if _, err := writer.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
					t.Fatal(err)
				}
			}
			var result map[string]any
			switch operation {
			case "admission":
				result = sqlitePortalRequest(t, f, alice, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, http.StatusServiceUnavailable)
			case "password":
				result = sqlitePortalRequest(t, f, alice, "POST", "/api/profile", map[string]string{"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": "Never-change-on-timeout-2026!"}, http.StatusServiceUnavailable)
			case "admin":
				result = sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", map[string]any{"realm": "local", "operation": "add_roles", "user": map[string]any{"username": "alice", "email": "alice@example.test", "roles": []string{"extra"}}}, http.StatusOK)
				if result["status"] != "failure" {
					t.Error("timed-out admin mutation published success")
				}
			}
			if result["code"] != "storage_unavailable" || result["entry"] != nil || result["roles"] != nil {
				t.Error("storage timeout did not return a safe unavailable result")
			}
		})
		// Release even after a subtest assertion fails; do not mask the next case.
		if _, err := writer.ExecContext(t.Context(), "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if operation == "password" {
			select {
			case err := <-s.outcome:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("mutation did not reach the real SQLite deadline")
				}
			default:
				t.Fatal("mutation never reached the SQLite store")
			}
		}
		var stored string
		var current uint64
		if err := writer.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE username='alice'").Scan(&stored, &current); err != nil {
			t.Fatal(err)
		}
		if stored != original || current != version {
			t.Fatal("timed-out mutation changed persistent credentials")
		}
		sqlitePortalRequest(t, f, alice, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, http.StatusOK)
	}
	// A released lock must restore actual login, without replacing the store or
	// rewriting the earlier proof; known rollback does not poison the handle.
	alice = f.login(t, "alice")
	sqlitePortalRequest(t, f, alice, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, http.StatusOK)
}

func TestE2ESQLiteProfileCommitFailure(t *testing.T) {
	for _, operation := range []string{"profile", "admin"} {
		t.Run(operation, func(t *testing.T) {
			f, cfg := newSQLiteDocumentsE2E(t, "/auth")
			token, admin := f.login(t, "alice"), f.login(t, "charlie")
			reader, err := sql.Open("sqlite", cfg.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			tx, err := reader.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var n int
			if err := tx.QueryRow("SELECT count(*) FROM accounts").Scan(&n); err != nil {
				t.Fatal(err)
			}
			if operation == "profile" {
				result := sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": "Never-publish-success-2026!"}, 503)
				if result["code"] != "commit_uncertain" || result["entry"] != nil {
					t.Fatal("uncertain HTTP mutation published success")
				}
			} else {
				result := sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", map[string]any{
					"realm": "local", "operation": "add_roles", "user": map[string]any{"username": "alice", "email": "alice@example.test", "roles": []string{"extra"}},
				}, 200)
				if result["status"] != "failure" || result["code"] != "commit_uncertain" || result["roles"] != nil {
					t.Fatal("uncertain admin mutation published results")
				}
			}
			tx.Rollback()
			reopened, err := accounts.New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			r := &requests.Request{User: requests.User{Username: "alice", Password: tests.TestPwd1}}
			if err := reopened.Request(operator.Authenticate, r); err != nil {
				t.Fatal("failed mutation changed password", err)
			}
			if len(r.User.Roles) != 1 || r.User.Roles[0] != "authp/user" {
				t.Fatal("failed mutation changed roles")
			}
		})
	}
}

// Delay the mutation after portal admission and before its transaction. The
// replacement login must not lend the old request authority when it resumes.
type delayedProfileStore struct {
	ids.IdentityStore
	entered, resume chan struct{}
}

func (s *delayedProfileStore) GetCapabilities() identity.StoreCapabilities {
	return s.IdentityStore.(identity.StoreCapabilityProvider).GetCapabilities()
}
func (s *delayedProfileStore) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	return s.IdentityStore.(interface {
		WithRefreshIdentity(context.Context, requests.AuthenticationEvidence, func(identity.RefreshIdentity) error) error
	}).WithRefreshIdentity(ctx, proof, apply)
}
func (s *delayedProfileStore) RequestWithIdentity(op operator.Type, r *requests.Request) error {
	if op == operator.ChangePassword {
		close(s.entered)
		select {
		case <-s.resume:
		case <-r.Upstream.Request.Context().Done():
			return r.Upstream.Request.Context().Err()
		}
	}
	return s.IdentityStore.(ids.IdentityRequestStore).RequestWithIdentity(op, r)
}

func TestE2EProfileRechecksSessionAtTransaction(t *testing.T) {
	for _, kind := range []string{"local", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var f *documentsE2E
			if kind == "sqlite" {
				f, _ = newSQLiteDocumentsE2E(t, "/auth")
			} else {
				f = newDocumentsE2E(t, "/auth", true, func(c *authn.PortalConfig) { c.API.ProfileEnabled = true })
			}
			s := &delayedProfileStore{IdentityStore: f.store, entered: make(chan struct{}), resume: make(chan struct{})}
			f.mu.Lock()
			f.portal.Close()
			f.store = s
			f.portal = f.newPortal()
			f.mu.Unlock()
			client := *f.client
			var err error
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			browser := &oidcE2EFixture{server: f.server, client: &client, issuer: f.server.URL + f.base}
			webAuthnEnrollmentLogin(t, browser, "alice", tests.TestPwd1)
			token := loginIdentityCookie(browser, "AUTHP_ACCESS_TOKEN")
			body, err := json.Marshal(map[string]string{"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": "Must-not-change-after-switch!"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", browser.issuer+"/api/profile", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			var response *http.Response
			var requestErr error
			done := make(chan struct{})
			go func() { response, requestErr = f.client.Do(req); close(done) }()
			var release sync.Once
			defer func() {
				release.Do(func() { close(s.resume) })
				cancel()
				<-done
				if response != nil {
					response.Body.Close()
				}
			}()
			select {
			case <-s.entered:
			case <-ctx.Done():
				t.Fatal("profile mutation never reached transaction boundary")
			}
			oidcE2EStatus(t, browser.request(t, "GET", "/login?fresh=1", nil, nil), 200)
			webAuthnEnrollmentLogin(t, browser, "bob", tests.TestPwd2)
			release.Do(func() { close(s.resume) })
			<-done
			if requestErr != nil || response == nil {
				t.Fatal("delayed profile request failed", requestErr)
			}
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("replaced request HTTP %d", response.StatusCode)
			}
			fresh := f.login(t, "alice") // Original password still works.
			sqlitePortalRequest(t, f, fresh, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, 200)
		})
	}
}

// TestE2ESQLiteAdminLifecycle qualifies every advertised management mutation
// through HTTP. Storage-only management tests do not establish this contract.
func TestE2ESQLiteAdminLifecycle(t *testing.T) {
	f, _ := newSQLiteDocumentsE2E(t, "/auth")
	admin, bob := f.login(t, "charlie"), f.login(t, "bob")
	selector := map[string]any{"username": "diana", "email": "diana@example.test", "name": "Diana Example", "roles": []string{"authp/user"}}
	manage := func(operation, want string) map[string]any {
		t.Helper()
		result := sqlitePortalRequest(t, f, admin, "POST", "/api/server/user", map[string]any{"realm": "local", "operation": operation, "user": selector}, 200)
		if want != "" && result["status"] != want {
			t.Fatalf("admin %s returned an unexpected outcome", operation)
		}
		if want == "failure" && (result["code"] != "operation_failed" || result["password"] != nil) {
			t.Fatalf("admin %s failure exposed credentials or lost its error code", operation)
		}
		return result
	}
	password := func(result map[string]any) string {
		t.Helper()
		secret, ok := result["password"].(string)
		if !ok || len(secret) < 12 {
			t.Fatal("successful management response omitted its generated credential")
		}
		return secret
	}
	login := func(secret string) string {
		t.Helper()
		client := *f.client
		client.Jar, _ = cookiejar.New(nil)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		fixture := &oidcE2EFixture{server: f.server, client: &client, issuer: f.server.URL + f.base}
		webAuthnEnrollmentLogin(t, fixture, "diana", secret)
		token := loginIdentityCookie(fixture, "AUTHP_ACCESS_TOKEN")
		if token == "" {
			t.Fatal("admin-provisioned credential did not complete browser login")
		}
		return token
	}
	denyLogin := func(secret string) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+f.base+"/basic/login/local", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.SetBasicAuth("diana", secret)
		client := *f.client
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal("denied login request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatal("revoked management credential still issued access")
		}
	}
	profile := func(token string, status int) map[string]any {
		t.Helper()
		return sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, status)
	}
	// The role boundary applies to direct requests, not only the manager menu.
	sqlitePortalRequest(t, f, bob, "POST", "/api/server/user", map[string]any{"realm": "local", "operation": "add", "user": selector}, 403)
	created := manage("add", "success")
	originalID := created["id"].(string)
	secret := password(created)
	token := login(secret)
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	if key.UserID != originalID {
		t.Fatal("provisioned identity differs from vault owner")
	}
	manage("add", "failure")
	profile(token, 200)
	selector["email"] = "wrong@example.test"
	manage("reset_password", "failure")
	selector["email"] = "diana@example.test"
	profile(token, 200)
	info := manage("info", "")
	if info["id"] != originalID || info["credential_version"] != float64(1) || info["disabled"] != false {
		t.Fatal("failed management requests changed the account")
	}
	selector["roles"] = []string{"team/reader"}
	manage("add_roles", "success")
	profile(token, 401)
	token = login(secret)
	selector["roles"] = []string{"authp/user", "team/editor"}
	result := manage("overwrite_roles", "success")
	roles, ok := result["roles"].([]any)
	if !ok || len(roles) != 2 || roles[0] != "authp/user" || roles[1] != "team/editor" {
		t.Fatal("role replacement did not return the complete resulting grants")
	}
	profile(token, 401)
	token = login(secret)
	manage("add_roles", "success") // Exact retry must retain current evidence.
	profile(token, 200)
	if sqlitePortalRequest(t, f, admin, "POST", "/api/server/reload", map[string]string{"realm": "local"}, 200)["status"] != "success" {
		t.Fatal("realm health reload failed")
	}
	profile(token, 200) // Health reload is not a new identity epoch.
	manage("disable", "success")
	if manage("info", "")["disabled"] != true {
		t.Fatal("disabled state not persisted")
	}
	profile(token, 401)
	sqlitePortalRequest(t, f, token, "GET", "/api/capabilities", nil, 401)
	f.message(t, token, "bootstrap", nil, 401)
	denyLogin(secret)
	manage("enable", "success")
	profile(token, 401) // Re-enabling cannot revive the earlier proof.
	token = login(secret)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
	replacement := password(manage("reset_password", "success"))
	profile(token, 401)
	denyLogin(secret)
	token = login(replacement)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
	manage("delete", "success")
	profile(token, 401)
	denyLogin(replacement)
	recreated := manage("add", "success")
	if recreated["id"] == originalID {
		t.Fatal("recreated username inherited immutable identity")
	}
	token = login(password(recreated))
	profile(token, 200)
	f.message(t, token, "key.fetch", nil, 404)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 404)
	profile(bob, 200)
}
