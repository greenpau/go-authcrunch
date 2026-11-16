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
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	accountsparser "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite/parser"
)

func newSQLiteDocumentsE2E(t *testing.T, base string) (*documentsE2E, *accounts.Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := accountsparser.NewSQLiteIdentityStoreConfigFromDirectives([]string{"name accounts", "realm local", cfgutil.EncodeArgs([]string{"path", filepath.Join(dir, "accounts.db")}), "timeout 5s"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := accounts.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, name := range []string{"alice", "bob", "charlie"} {
		password := tests.TestPwd1
		if name == "bob" {
			password = tests.TestPwd2
		}
		roles := []string{"authp/user"}
		if name == "charlie" {
			roles = []string{"authp/admin"}
		}
		if _, err := store.Create(t.Context(), &accounts.Account{Username: name, Email: name + "@example.test", Name: name, Roles: roles}, password); err != nil {
			t.Fatal(err)
		}
	}
	f := newDocumentsRuntime(t, base, true, store, filepath.Join(dir, "documents.db"), func(c *authn.PortalConfig) { c.API.ProfileEnabled = true; c.API.AdminEnabled = true })
	f.declaredMount = base
	return f, cfg
}

func TestE2ESQLiteDocuments(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*testing.T, *documentsE2E)
	}{
		{"authorization_persistence", runDocumentsAuthorizationPersistenceAndIdentity},
		{"request_boundaries", runDocumentsRequestBoundariesAndReset},
		{"reset_binding", runDocumentsResetConfirmationBinding},
		{"session_replacement", runDocumentsRejectsReplacedSessionToken},
		{"browser_encryption", runDocumentsBrowserEncryption},
	} {
		t.Run(test.name, func(t *testing.T) { f, _ := newSQLiteDocumentsE2E(t, "/tenant/xauth"); test.run(t, f) })
	}
}

func TestE2ESQLiteDocumentsRevocationRestartAndSource(t *testing.T) {
	f, cfg := newSQLiteDocumentsE2E(t, "/auth")
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := documentsDecode[documents.File](t, f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 200))
	f.message(t, token, "file.manifest", map[string]any{"id": file.ID, "manifest": documents.Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: documentsEnvelope(key)}}, 200)
	other, err := accounts.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	documentsDelayedRequest(t, f, token, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, func() {
		if _, err := other.AddUserRoles("alice", "alice@example.test", []string{"extra"}); err != nil {
			t.Fatal(err)
		}
	}, 401)
	token = f.login(t, "alice")
	f.message(t, token, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))}, 200)
	f.message(t, token, "file.commit", map[string]any{"id": file.ID}, 200)
	admin := f.login(t, "charlie")
	for _, op := range []string{"file.fetch", "file.delete", "share.list"} {
		f.message(t, admin, op, map[string]any{"id": file.ID}, 404)
	}
	f.mu.Lock()
	f.portal.Close()
	f.store.(*accounts.Store).Close()
	reopened, err := accounts.New(t.Context(), cfg)
	if err != nil {
		f.mu.Unlock()
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	f.store = reopened
	f.portal = f.newPortal()
	f.mu.Unlock()
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 401)
	token = f.login(t, "alice")
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
	// Reopening the same persistent account UUID under a different source cannot
	// adopt its vault, even though credentials and account selectors still match.
	renamed := *cfg
	renamed.Name = "other-accounts"
	foreign, err := accounts.New(t.Context(), &renamed)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	f.mu.Lock()
	f.portal.Close()
	f.store = foreign
	f.portal = f.newPortal()
	f.mu.Unlock()
	token = f.login(t, "alice")
	f.message(t, token, "bootstrap", nil, 403)
	f.message(t, token, "key.reset", map[string]any{"user_id": key.UserID, "key_id": key.KeyID}, 403)
	f.mu.Lock()
	f.portal.Close()
	f.store = reopened
	f.portal = f.newPortal()
	f.mu.Unlock()
	token = f.login(t, "alice")
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
}

// Model an outer identity transaction whose outcome is unknown after the
// callback's independent Documents transaction completed. Never expose success,
// even if the outer error also carries an authorization denial.
type uncertainDocumentsIdentity struct {
	*accounts.Store
	fail atomic.Bool
}

func (s *uncertainDocumentsIdentity) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	err := s.Store.WithRefreshIdentity(ctx, proof, apply)
	if err == nil && s.fail.Load() {
		return errors.Join(sqlitedb.ErrCommitUncertain, identity.ErrRefreshIdentityDenied)
	}
	return err
}

// Pause admission when the backend creates its operation budget, after its
// initial availability check but before it acquires the SQL connection. This
// makes the queued-request race deterministic without sleeps or storage mocks.
type delayedIdentityDeadline struct {
	context.Context
	entered, resume chan struct{}
	once            sync.Once
}

func (c *delayedIdentityDeadline) Deadline() (time.Time, bool) {
	c.once.Do(func() { close(c.entered) })
	select {
	case <-c.resume:
	case <-c.Done():
	}
	return c.Context.Deadline()
}

type queuedDocumentsIdentity struct {
	*accounts.Store
	armed, called   atomic.Bool
	entered, resume chan struct{}
}

func (s *queuedDocumentsIdentity) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	if !s.armed.Load() {
		return s.Store.WithRefreshIdentity(ctx, proof, apply)
	}
	budget := &delayedIdentityDeadline{Context: ctx, entered: s.entered, resume: s.resume}
	return s.Store.WithRefreshIdentity(budget, proof, func(current identity.RefreshIdentity) error {
		s.called.Store(true)
		return apply(current)
	})
}

func TestE2ESQLiteDocumentsQueuedQuarantine(t *testing.T) {
	f, cfg := newSQLiteDocumentsE2E(t, "/auth")
	store := &queuedDocumentsIdentity{Store: f.store.(*accounts.Store), entered: make(chan struct{}), resume: make(chan struct{})}
	f.mu.Lock()
	f.portal.Close()
	f.store = store
	f.portal = f.newPortal()
	f.mu.Unlock()
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	method, path, _ := documentsRequest(t, "file.delete", map[string]any{"id": file.ID})
	req, err := http.NewRequestWithContext(ctx, method, f.server.URL+f.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	store.armed.Store(true)
	finished := make(chan struct{})
	var response *http.Response
	var requestErr error
	go func() { response, requestErr = f.client.Do(req); close(finished) }()
	var release sync.Once
	defer func() {
		release.Do(func() { close(store.resume) })
		cancel()
		<-finished
		if response != nil {
			response.Body.Close()
		}
	}()
	select {
	case <-store.entered:
	case <-ctx.Done():
		t.Fatal("Documents did not reach identity transaction admission")
	}
	dsn := (&url.URL{Scheme: "file", Path: cfg.Path, RawQuery: "mode=rw"}).String()
	readerDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer readerDB.Close()
	reader, err := readerDB.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.QueryRowContext(t.Context(), "SELECT count(*) FROM accounts").Scan(&count); err != nil {
		t.Fatal(err)
	}
	// An independent reader forces a real password COMMIT failure and
	// quarantines the account handle while the DELETE is awaiting admission.
	if err := store.SetPassword(t.Context(), "alice", "alice@example.test", tests.TestPwd2); !errors.Is(err, accounts.ErrCommitUncertain) {
		t.Fatal("password mutation did not fail at COMMIT", err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	release.Do(func() { close(store.resume) })
	<-finished
	if requestErr != nil || response == nil {
		t.Fatal("queued Documents request failed at transport")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("quarantined identity handle published HTTP success")
	}
	result := documentsDecode[map[string]any](t, body)
	if result["code"] != "storage_unavailable" || result["success"] != nil || store.called.Load() {
		t.Error("queued DELETE entered its callback after identity quarantine")
	}
	openAPIJourneyResponse(t, f.server.URL+strings.TrimSuffix(f.base, "/"), req.URL, method, response.StatusCode, response.Header, body)
	// Drain and reopen, then reconcile using fresh proof and the unchanged
	// original password. The queued deletion must not have changed ciphertext.
	reopened, err := accounts.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	f.mu.Lock()
	f.portal.Close()
	store.Close()
	f.store = reopened
	f.portal = f.newPortal()
	f.mu.Unlock()
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, http.StatusUnauthorized)
	token = f.login(t, "alice")
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, http.StatusOK)
	f.message(t, token, "file.delete", map[string]any{"id": file.ID}, http.StatusOK)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, http.StatusNotFound)
}

// A backend budget can expire before the containing HTTP request. Delay the
// identity callback across that real SQLite deadline, then perform Documents
// work using the still-live request context, just as the production adapter does.
type expiringDocumentsIdentity struct {
	*accounts.Store
	armed   atomic.Bool
	entered chan context.Context
	resume  chan struct{}
}

func (s *expiringDocumentsIdentity) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	if !s.armed.Load() {
		return s.Store.WithRefreshIdentity(ctx, proof, apply)
	}
	budget, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	return s.Store.WithRefreshIdentity(budget, proof, func(current identity.RefreshIdentity) error {
		s.entered <- budget
		select {
		case <-s.resume:
			return apply(current)
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func TestE2ESQLiteDocumentsExpiredCallbackLock(t *testing.T) {
	for _, mode := range []string{"committed", "uncertain"} {
		t.Run(mode, func(t *testing.T) { runSQLiteDocumentsExpiredCallbackLock(t, mode == "uncertain") })
	}
}

func runSQLiteDocumentsExpiredCallbackLock(t *testing.T, failCommit bool) {
	t.Helper()
	f, cfg := newSQLiteDocumentsE2E(t, "/auth")
	store := &expiringDocumentsIdentity{Store: f.store.(*accounts.Store), entered: make(chan context.Context, 1), resume: make(chan struct{})}
	f.mu.Lock()
	f.portal.Close()
	f.store = store
	f.portal = f.newPortal()
	f.mu.Unlock()
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	otherConfig := *cfg
	otherConfig.Timeout = "100ms"
	other, err := accounts.New(t.Context(), &otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	before, err := other.FetchUserData("alice", "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	method, path, _ := documentsRequest(t, "file.delete", map[string]any{"id": file.ID})
	req, err := http.NewRequestWithContext(ctx, method, f.server.URL+f.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	store.armed.Store(true)
	var response *http.Response
	var requestErr error
	finished := make(chan struct{})
	go func() { response, requestErr = f.client.Do(req); close(finished) }()
	var release sync.Once
	defer func() {
		release.Do(func() { close(store.resume) })
		cancel()
		<-finished
		if response != nil {
			response.Body.Close()
		}
	}()
	select {
	case budget := <-store.entered:
		<-budget.Done()
	case <-ctx.Done():
		t.Fatal("Documents never reached the identity callback")
	}
	if _, err := other.AddUserRoles("alice", "alice@example.test", []string{"extra"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Error("credential revocation entered while the expired identity callback was executing")
	}
	var reader *sql.Tx
	if failCommit {
		// A reader on another connection makes the independent DELETE's COMMIT
		// fail after the outer account budget expires. Preserve both facts.
		dsn := (&url.URL{Scheme: "file", Path: f.database, RawQuery: "mode=rw"}).String()
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		reader, err = db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Rollback()
		var count int
		if err := reader.QueryRowContext(t.Context(), "SELECT count(*) FROM files").Scan(&count); err != nil || count != 1 {
			t.Fatal("Documents reader did not acquire its lock", err)
		}
	}
	release.Do(func() { close(store.resume) })
	<-finished
	if requestErr != nil || response == nil {
		t.Fatal("expired Documents request failed at transport")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("expired identity transaction published HTTP success")
	}
	result := documentsDecode[map[string]any](t, body)
	if result["code"] != "commit_uncertain" || result["success"] != nil {
		t.Error("completed Documents mutation lost its reconciliation signal")
	}
	openAPIJourneyResponse(t, f.server.URL+strings.TrimSuffix(f.base, "/"), req.URL, method, response.StatusCode, response.Header, body)
	store.armed.Store(false)
	after, err := other.FetchUserData("alice", "alice@example.test")
	if err != nil || after["credential_version"] != before["credential_version"] {
		t.Error("blocked revocation changed the credential generation")
	}
	// Reconcile without replaying delete. Only the independently failed COMMIT
	// quarantines Documents; cancellation leaves the account database healthy.
	wantFile := http.StatusNotFound
	if failCommit {
		if err := reader.Rollback(); err != nil {
			t.Fatal(err)
		}
		unavailable := documentsDecode[map[string]any](t, f.message(t, token, "key.fetch", nil, http.StatusServiceUnavailable))
		if unavailable["code"] != "storage_unavailable" {
			t.Fatal("failed Documents COMMIT did not quarantine its handle")
		}
		f.mu.Lock()
		f.portal.Close()
		f.portal = f.newPortal()
		f.mu.Unlock()
		wantFile = http.StatusOK
	}
	token = f.login(t, "alice")
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, wantFile)
	f.message(t, token, "key.fetch", nil, http.StatusOK)
	if _, err := other.AddUserRoles("alice", "alice@example.test", []string{"extra"}); err != nil {
		t.Fatal("revocation did not recover after the callback returned")
	}
	f.message(t, token, "key.fetch", nil, http.StatusUnauthorized)
	token = f.login(t, "alice")
	f.message(t, token, "key.fetch", nil, http.StatusOK)
}

func TestE2ESQLiteDocumentsOuterCommitUncertainty(t *testing.T) {
	f, _ := newSQLiteDocumentsE2E(t, "/auth")
	store := &uncertainDocumentsIdentity{Store: f.store.(*accounts.Store)}
	f.mu.Lock()
	f.portal.Close()
	f.store = store
	f.portal = f.newPortal()
	f.mu.Unlock()
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	store.fail.Store(true)
	result := documentsDecode[map[string]any](t, f.message(t, token, "file.delete", map[string]any{"id": file.ID}, 503))
	if result["success"] != nil || result["code"] != "commit_uncertain" {
		t.Fatal("uncertain transaction published success or lost its reconciliation code")
	}
	store.fail.Store(false)
	// Reconcile, do not replay: the deletion committed before the outer failure.
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 404)
	f.message(t, token, "key.fetch", nil, 200)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := documentsDecode[map[string]any](t, f.message(t, token, "bootstrap", nil, 503))
	if unavailable["code"] != "storage_unavailable" {
		t.Fatal("closed store did not report storage unavailability")
	}
}
