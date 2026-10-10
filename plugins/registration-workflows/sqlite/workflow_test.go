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
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/messaging"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	notifications "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
)

const testPassword = "Synthetic-registration-password-2026!"

func setupWorkflow(t *testing.T) (*Workflow, *Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), &accounts.Config{Name: "accounts", Realm: "staff", Path: filepath.Join(dir, "accounts.db"), Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	out, err := notifications.New(t.Context(), &notifications.Config{Name: "mail", Path: filepath.Join(dir, "outbox.db"), Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	config := &Config{Name: "registration", Path: filepath.Join(dir, "registration.db"), Timeout: "5s", IdentityStore: "accounts", Realm: "staff", EmailProvider: "mail", PublicOrigin: "https://portal.example.test"}
	w, err := New(t.Context(), config, store, out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w, config
}
func enrollment(username string) map[string]string {
	return map[string]string{"username": username, "email": username + "@example.test", "password": testPassword, "registration_code": "ABC123", "realm_name": "staff"}
}
func TestRegistrationSingleUseAndLockout(t *testing.T) {
	w, config := setupWorkflow(t)
	if config.BasePath != "" {
		t.Fatal("mutated caller config")
	}
	id := strings.Repeat("a", 64)
	data := enrollment("alice")
	if err := w.AddRegistrationEntry(id, data); err != nil {
		t.Fatal(err)
	}
	got, err := w.GetRegistrationEntry(id)
	if err != nil || len(got) != 4 || got["username"] != "alice" {
		t.Fatal("unsafe metadata", err)
	}
	got["username"] = "attacker"
	if data["password"] != testPassword {
		t.Fatal("mutated caller map")
	}
	if err := w.AddRegistrationEntry(id, data); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	for range 4 {
		if err := w.ConfirmRegistration(t.Context(), id, "incorrect"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if err := w.ConfirmRegistration(t.Context(), id, "ABC123"); err != nil {
		t.Fatal(err)
	}
	account, err := w.store.FetchUserData("alice", "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if roles := account["roles"].([]string); len(roles) != 1 || roles[0] != "authp/user" {
		t.Fatal("untrusted role")
	}
	if _, err := w.GetRegistrationEntry(id); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err := w.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err := w.store.DeleteUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := w.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal("spent enrollment revived account", err)
	}
	id = strings.Repeat("b", 64)
	if err := w.AddRegistrationEntry(id, enrollment("bob")); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := w.ConfirmRegistration(t.Context(), id, "bad"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(t.Context(), config, w.store, w.outbox)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal("restart cleared attempt budget", err)
	}
	if _, err := w.store.FetchUserData("bob", "bob@example.test"); err == nil {
		t.Fatal("locked registration created account")
	}
}
func TestRegistrationConcurrentConfirmationAndBinding(t *testing.T) {
	w, config := setupWorkflow(t)
	id := strings.Repeat("c", 64)
	if err := w.AddRegistrationEntry(id, enrollment("alice")); err != nil {
		t.Fatal(err)
	}
	changed := *config
	changed.PublicOrigin = "https://other.example.test"
	other, err := New(t.Context(), &changed, w.store, w.outbox)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong audience", err)
	}
	other.Close()
	second, err := New(t.Context(), config, w.store, w.outbox)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, instance := range []*Workflow{w, second} {
		wg.Go(func() { <-start; results <- instance.ConfirmRegistration(t.Context(), id, "ABC123") })
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrDenied) && !errors.Is(err, ErrCommitUncertain) {
			t.Fatal(err)
		}
	}
	if success > 1 {
		t.Fatal("confirmation not single-use")
	}
	// Concurrent BEGIN attempts can briefly hold read locks and make COMMIT
	// return BUSY. This is an allowed uncertain outcome, never a second success.
	// Drain and reopen before reconciling; never retry a quarantined handle.
	before, err := w.store.FetchUserData("alice", "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := New(t.Context(), config, w.store, w.outbox)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	err = fresh.ConfirmRegistration(t.Context(), id, "ABC123")
	if success == 0 {
		if err != nil {
			t.Fatal("uncertain confirmation did not recover", err)
		}
	} else if !errors.Is(err, ErrDenied) {
		t.Fatal("confirmed enrollment was consumed again", err)
	}
	after, err := w.store.FetchUserData("alice", "alice@example.test")
	if err != nil || before["id"] != after["id"] {
		t.Fatal("reconciliation replaced account", err)
	}
	if err := fresh.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal("reconciled confirmation replayed", err)
	}
}
func TestRegistrationCrashRecovery(t *testing.T) {
	for _, deleteAccount := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry", true: "deleted account"}[deleteAccount], func(t *testing.T) {
			w, config := setupWorkflow(t)
			id := strings.Repeat("d", 64)
			if err := w.AddRegistrationEntry(id, enrollment("alice")); err != nil {
				t.Fatal(err)
			}
			reader, err := New(t.Context(), config, w.store, w.outbox)
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
					if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM registrations").Scan(&count); err != nil {
						return err
					}
					close(locked)
					<-release
					return nil
				})
			}()
			<-locked
			err = w.ConfirmRegistration(t.Context(), id, "ABC123")
			close(release)
			if readErr := <-done; readErr != nil {
				t.Fatal(readErr)
			}
			if !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("fixture did not force ambiguous pending-state commit", err)
			}
			before, err := w.store.FetchUserData("alice", "alice@example.test")
			if err != nil {
				t.Fatal("account commit did not precede interrupted confirmation", err)
			}
			w.Close()
			reader.Close()
			if deleteAccount {
				if err := w.store.DeleteUser("alice", "alice@example.test"); err != nil {
					t.Fatal(err)
				}
			}
			fresh, err := New(t.Context(), config, w.store, w.outbox)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			err = fresh.ConfirmRegistration(t.Context(), id, "ABC123")
			if deleteAccount {
				if err == nil {
					t.Fatal("deleted enrollment resurrected account")
				}
				if _, err := w.store.FetchUserData("alice", "alice@example.test"); err == nil {
					t.Fatal("deleted account exists")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := w.store.FetchUserData("alice", "alice@example.test")
			if err != nil || before["id"] != after["id"] {
				t.Fatal("retry replaced identity", err)
			}
		})
	}
}
func TestRegistrationValidationExpiryAndMetadata(t *testing.T) {
	w, config := setupWorkflow(t)
	id := strings.Repeat("e", 64)
	for _, mutate := range []func(map[string]string){func(d map[string]string) { d["username"] = "nobody" }, func(d map[string]string) { d["realm_name"] = "other" }, func(d map[string]string) { d["password"] = "short" }, func(d map[string]string) { d["password"] = "bcrypt:malformed" }, func(d map[string]string) { d["email"] = "Bad <alice@example.test>" }, func(d map[string]string) { d["registration_code"] = "x" }} {
		d := enrollment("alice")
		mutate(d)
		if err := w.AddRegistrationEntry(id, d); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if err := w.AddRegistrationEntry(id, enrollment("alice")); err != nil {
		t.Fatal(err)
	}
	if err := w.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		p, err := w.read(ctx, tx, id)
		if err != nil {
			return err
		}
		if string(p.password) == testPassword || string(p.code) == "ABC123" || !strings.HasPrefix(string(p.password), "$2") {
			t.Fatal("plaintext credential stored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data := enrollment("mallory")
	data["template"] = "registration_confirmation"
	data["registration_id"] = id
	data["registration_url"] = "https://evil.example.test"
	data["session_id"] = "session"
	data["request_id"] = "request"
	data["timestamp"] = "now"
	data["src_ip"] = "192.0.2.1"
	data["src_conn_ip"] = "192.0.2.2"
	snapshot := maps.Clone(data)
	if err := w.Notify(data); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(snapshot, data) {
		t.Fatal("notification mutated inputs")
	}
	msg, err := w.outbox.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Recipients[0] != "alice@example.test" || strings.Contains(msg.Body, "evil.example.test") || !strings.Contains(msg.Body, "portal.example.test") {
		t.Fatal("notification used unbound recipient/origin")
	}
	if err := w.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE registrations SET expires=1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if w.Validate() != nil || w.Activate(nil) != nil || w.Kind() != "sqlite" || w.GetName() != "registration" || w.GetRealmName() != "staff" || w.GetIdentityStoreName() != "accounts" || w.GetEmailProvider() != "mail" {
		t.Fatal("metadata contract")
	}
	metadata := w.AsMap()
	if len(metadata) != 4 {
		t.Fatal("unsafe metadata")
	}
	metadata["name"] = "mutated"
	if w.AsMap()["name"] != "registration" {
		t.Fatal("metadata alias")
	}
	w.SetRealmName("attacker")
	if w.GetRealmName() != "staff" {
		t.Fatal("rebound realm")
	}
	cfg := &messaging.Config{}
	if err := cfg.AddProvider("mail", w.outbox); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMessaging(cfg); err != nil {
		t.Fatal(err)
	}
	if w.AddUser(nil) == nil || w.SetMessaging(nil) == nil || w.Notify(nil) == nil {
		t.Fatal("unsupported operation accepted")
	}
	if w.SetCredentials(nil) != nil || w.GetCode() != "" || w.GetRequireAcceptTerms() || w.GetRequireDomainMX() || len(w.GetDomainRestrictions()) != 0 || len(w.GetAdminEmails()) != 0 || w.GetTermsConditionsLink() != "" || w.GetPrivacyPolicyLink() != "" || w.GetTitle() == "" || w.GetUsernamePolicyRegex() == "" || w.GetPasswordPolicyRegex() == "" || w.GetUsernamePolicySummary() == "" || w.GetPasswordPolicySummary() == "" {
		t.Fatal("fixed policy contract")
	}
	wrong := *config
	wrong.Realm = "other"
	if got, err := New(t.Context(), &wrong, w.store, w.outbox); got != nil || err == nil {
		t.Fatal("mismatched binding accepted")
	}
	id = strings.Repeat("f", 64)
	if err := w.AddRegistrationEntry(id, enrollment("bob")); err != nil {
		t.Fatal(err)
	}
	if err := w.DeleteRegistrationEntry(id); err != nil {
		t.Fatal(err)
	}
	if err := w.ConfirmRegistration(t.Context(), id, "ABC123"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	// A canceled confirmation must leave its pending entry usable.
	id = strings.Repeat("g", 64)
	if err := w.AddRegistrationEntry(id, enrollment("carol")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := w.ConfirmRegistration(ctx, id, "ABC123"); err == nil {
		t.Fatal("canceled confirmation accepted")
	}
	if _, err := w.GetRegistrationEntry(id); err != nil {
		t.Fatal(err)
	}
	if err := w.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.ConfirmRegistration(t.Context(), id, "ABC123"); err == nil {
		t.Fatal("closed account backend accepted")
	}
	if _, err := w.GetRegistrationEntry(id); err != nil {
		t.Fatal("failed account creation deleted pending evidence", err)
	}
}

func TestRegistrationCapacityAndConfig(t *testing.T) {
	w, config := setupWorkflow(t)
	for _, change := range []func(*Config){func(c *Config) { c.Name = "" }, func(c *Config) { c.Path = "relative" }, func(c *Config) { c.Realm = "../other" }, func(c *Config) { c.IdentityStore = "" }, func(c *Config) { c.EmailProvider = "" }, func(c *Config) { c.PublicOrigin = "https://EXAMPLE.test" }, func(c *Config) { c.Timeout = "0s" }, func(c *Config) { c.BasePath = "/a?b" }} {
		c := *config
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid typed config accepted")
		}
	}
	if (*Config)(nil).Validate() == nil {
		t.Fatal("nil config accepted")
	}
	if got, err := New(t.Context(), nil, w.store, w.outbox); got != nil || err == nil {
		t.Fatal("nil constructor config accepted")
	}
	id := strings.Repeat("h", 64)
	if err := w.AddRegistrationEntry(id, enrollment("alice")); err != nil {
		t.Fatal(err)
	}
	if err := w.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO registrations SELECT CAST(printf('%064d',n.x) AS BLOB),binding,username,email,enrollment,password,code,expires,attempts,state,return_url FROM registrations CROSS JOIN (WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<9999) SELECT x FROM n) n")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddRegistrationEntry(strings.Repeat("i", 64), enrollment("bob")); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if _, err := w.GetRegistrationEntry(id); err != nil {
		t.Fatal("capacity refusal evicted existing entry", err)
	}
}

func TestRegistrationAccountCommitUncertainty(t *testing.T) {
	w, config := setupWorkflow(t)
	id := strings.Repeat("j", 64)
	if err := w.AddRegistrationEntry(id, enrollment("alice")); err != nil {
		t.Fatal(err)
	}
	accountPath := filepath.Join(filepath.Dir(config.Path), "accounts.db")
	reader, err := sql.Open("sqlite", accountPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(t.Context(), "SELECT count(*) FROM accounts").Scan(&count); err != nil {
		t.Fatal(err)
	}
	err = w.ConfirmRegistration(t.Context(), id, "ABC123")
	if !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("account commit uncertainty was hidden", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.GetRegistrationEntry(id); err != nil {
		t.Fatal("uncertain account commit lost pending entry", err)
	}
	w.store.Close()
	w.Close()
	replacement, err := accounts.New(t.Context(), &accounts.Config{Name: "accounts", Realm: "staff", Path: accountPath, Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	fresh, err := New(t.Context(), config, replacement, w.outbox)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := fresh.ConfirmRegistration(t.Context(), id, "ABC123"); err != nil {
		t.Fatal("failed to recover account commit", err)
	}
}

// A live code must not gain extra lifetime while waiting for another database.
func TestRegistrationExpiryDuringAccountLock(t *testing.T) {
	w, config := setupWorkflow(t)
	id := strings.Repeat("k", 64)
	if err := w.AddRegistrationEntry(id, enrollment("alice")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Truncate(time.Second).Add(3 * time.Second)
	if err := w.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE registrations SET expires=?", deadline.Unix())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	blocker, err := sql.Open("sqlite", filepath.Join(filepath.Dir(config.Path), "accounts.db"))
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
	done := make(chan error, 1)
	go func() { done <- w.ConfirmRegistration(t.Context(), id, "ABC123") }()
	// The account lock is held until the credential is definitely expired.
	timer := time.NewTimer(time.Until(deadline) + 100*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, err := conn.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired confirmation created an account after its lock wait")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("confirmation exceeded bounded lock wait")
	}
	if _, err := w.store.FetchUserData("alice", "alice@example.test"); err == nil {
		t.Fatal("expired registration persisted an account")
	}
}

func TestRegistrationDestinationSurvivesRestart(t *testing.T) {
	w, config := setupWorkflow(t)
	id := strings.Repeat("d", 64)
	data := enrollment("destination")
	destination := "https://app.test/" + strings.Repeat("x", 8000)
	data["return_url"] = destination
	if err := w.AddRegistrationEntry(id, data); err != nil {
		t.Fatal(err)
	}
	data["return_url"] = "https://app.test/replaced"
	if err := w.AddRegistrationEntry(id, data); !errors.Is(err, ErrConflict) {
		t.Fatal("mutable destination", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(t.Context(), config, w.store, w.outbox)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result, err := reopened.GetRegistrationEntry(id)
	if err != nil || result["return_url"] != destination {
		t.Fatal("lost destination after restart", err)
	}
	data["return_url"] = strings.Repeat("x", 16385)
	if err := reopened.AddRegistrationEntry(strings.Repeat("e", 64), data); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded destination", err)
	}
	if err := reopened.ConfirmRegistration(t.Context(), id, "ABC123"); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetRegistrationEntry(id); !errors.Is(err, ErrDenied) {
		t.Fatal("spent destination published", err)
	}
	var retained string
	if err := reopened.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT return_url FROM registrations").Scan(&retained)
	}); err != nil || retained != "" {
		t.Fatal("completed registration retained navigation metadata", err)
	}
}
