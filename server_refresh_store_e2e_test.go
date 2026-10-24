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
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	refreshsqlite "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
	"go.uber.org/zap"
)

// Every replacement closes the actual root and borrowed SQLite handle, then
// constructs both again from the same configuration and durable files. The TLS
// listener is intentionally stable: this is root replacement, not an OS restart.
type managedRootTLS struct {
	*selectedRootTLS
	databaseConfig refreshsqlite.Config
	database       *refreshsqlite.Store
	generation     tokenrefresh.Generation
}

type recordingManagedStore struct {
	tokenrefresh.ManagedStore
	generation tokenrefresh.Generation
}

func (s *recordingManagedStore) ActivateGeneration(ctx context.Context, g tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	view, err := s.ManagedStore.ActivateGeneration(ctx, g)
	if err == nil {
		s.generation = g
	}
	return view, err
}

func newManagedRootTLS(t *testing.T) *managedRootTLS {
	t.Helper()
	base := newSelectedRootTLS(t, true)
	base.stop(t)
	directory := filepath.Join(t.TempDir(), "refresh")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	f := &managedRootTLS{selectedRootTLS: base, databaseConfig: refreshsqlite.Config{Path: filepath.Join(directory, "refresh.db"), MaxSessions: 1, MaxRotations: 16}}
	if err := f.databaseConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	descriptor, err := tokenrefresh.NewExternalStoreConfig("durable", "sqlite", 1, 16, f.databaseConfig)
	if err != nil {
		t.Fatal(err)
	}
	var cfg authcrunch.Config
	if json.Unmarshal(base.config, &cfg) != nil {
		t.Fatal("root config snapshot failed")
	}
	cfg.ExternalRefreshStores = []*tokenrefresh.ExternalStoreConfig{descriptor}
	selected := cfg.AuthenticationPortals[0].RefreshTokens
	selected.Store = "durable"
	selected.MaxSessions, selected.MaxRotations = 1, 16
	f.config = fixture.JSON(t, &cfg)
	f.start(t)
	t.Cleanup(func() { f.server.Close(); f.stop(t) })
	return f
}

func (f *managedRootTLS) start(t *testing.T) {
	t.Helper()
	database, err := refreshsqlite.New(t.Context(), &f.databaseConfig)
	if err != nil {
		t.Fatal("managed SQLite open failed", err)
	}
	f.database = database
	var cfg authcrunch.Config
	if json.Unmarshal(f.config, &cfg) != nil {
		t.Fatal("root config snapshot failed")
	}
	recording := &recordingManagedStore{ManagedStore: database}
	root, err := authcrunch.NewServerWithOptions(&cfg, zap.NewNop(), authcrunch.ServerOptions{
		AccessSigners: map[string]kms.AccessSigner{"access": f.key.Signer},
		RefreshStores: map[string]tokenrefresh.ManagedStore{"durable": recording},
	})
	if err != nil {
		_ = database.Close()
		f.database = nil
		t.Fatal("managed root construction failed", err)
	}
	f.generation = recording.generation
	f.mu.Lock()
	f.root = root
	f.mu.Unlock()
}

func (f *managedRootTLS) stop(t *testing.T) {
	t.Helper()
	f.selectedRootTLS.stop(t)
	if f.database != nil {
		if err := f.database.CheckReady(context.Background()); err != nil {
			t.Error("root closed or damaged borrowed refresh store")
		}
		if err := f.database.Close(); err != nil {
			t.Error("managed SQLite close failed")
		}
		f.database = nil
	}
}

func (f *managedRootTLS) restart(t *testing.T) { t.Helper(); f.stop(t); f.start(t) }

func (f *managedRootTLS) logout(t *testing.T, token string) {
	t.Helper()
	status, headers, _ := f.request(t, http.MethodPost, "/auth/api/logout", map[string]string{"refresh_token": token}, "", false)
	if status != http.StatusOK || headers.Get("Cache-Control") != "no-store" || headers.Get("Authorization") != "" {
		t.Fatal("managed native logout failed")
	}
}

func (f *managedRootTLS) assertContinuity(t *testing.T, before, after apiauth.AuthResponse) {
	t.Helper()
	beforeClaims, err := f.key.Store(t).VerifyAccessToken(t.Context(), before.AccessToken)
	if err != nil {
		t.Fatal("original selected access token failed verification")
	}
	afterClaims, err := f.key.Store(t).VerifyAccessToken(t.Context(), after.AccessToken)
	if err != nil {
		t.Fatal("renewed selected access token failed verification")
	}
	if before.SessionID == "" || before.SessionID != after.SessionID || before.RefreshToken == after.RefreshToken || beforeClaims["sub"] != afterClaims["sub"] || beforeClaims["sid"] != afterClaims["sid"] || beforeClaims["auth_time"] != afterClaims["auth_time"] || beforeClaims["jti"] == afterClaims["jti"] {
		t.Fatal("durable refresh lost original identity/evidence or failed rotation")
	}
	if status, _, _ := f.request(t, http.MethodGet, "/protected", nil, after.AccessToken, false); status != http.StatusNoContent {
		t.Fatal("actual policy rejected durable refresh output")
	}
}

func TestE2EServerManagedRefreshPersistence(t *testing.T) {
	f := newManagedRootTLS(t)
	first := f.login(t, "body")
	f.restart(t)
	next := f.refresh(t, first.RefreshToken, http.StatusOK)
	f.assertContinuity(t, first, next)
	f.restart(t)
	// A spent digest survives close/reopen and revokes its current descendant.
	f.refresh(t, first.RefreshToken, http.StatusUnauthorized)
	f.refresh(t, next.RefreshToken, http.StatusUnauthorized)
	fresh := f.login(t, "body") // replay removed the complete family at capacity one
	f.logout(t, fresh.RefreshToken)
	f.restart(t)
	f.refresh(t, fresh.RefreshToken, http.StatusUnauthorized)
	control := f.login(t, "body")
	f.refresh(t, control.RefreshToken, http.StatusOK)
}

func TestE2EServerManagedRefreshRemovalGeneration(t *testing.T) {
	f := newManagedRootTLS(t)
	first := f.login(t, "body")
	original := append([]byte(nil), f.config...)
	f.stop(t)
	// This real intermediate root contains no portal and no selected store. It
	// still advances the durable whole-configuration epoch, without opening SQLite.
	var removed authcrunch.Config
	if json.Unmarshal(original, &removed) != nil {
		t.Fatal("root config snapshot failed")
	}
	removed.AuthenticationPortals = nil
	removed.IdentityStores = nil
	removed.ExternalRefreshStores = nil
	root, err := authcrunch.NewServerWithOptions(&removed, zap.NewNop(), authcrunch.ServerOptions{AccessSigners: map[string]kms.AccessSigner{"access": f.key.Signer}})
	if err != nil {
		t.Fatal("root without selected portal failed", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	f.config = original
	f.start(t)
	f.refresh(t, first.RefreshToken, http.StatusUnauthorized)
	// Admission at capacity one proves the absent portal's old family was retired,
	// rather than just becoming unreachable and retaining its slot indefinitely.
	control := f.login(t, "body")
	f.refresh(t, control.RefreshToken, http.StatusOK)
}

func TestE2EServerManagedRefreshLoadedTrustGeneration(t *testing.T) {
	f := newManagedRootTLS(t)
	first := f.login(t, "body")
	f.stop(t)
	original, err := os.ReadFile(f.auxiliary.PublicFile)
	if err != nil {
		t.Fatal(err)
	}
	// Equivalent public authority encoded differently must preserve generation.
	equivalent := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&f.auxiliary.Key.PublicKey)})
	if err := os.WriteFile(f.auxiliary.PublicFile, equivalent, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	next := f.refresh(t, first.RefreshToken, http.StatusOK)
	f.assertContinuity(t, first, next)
	f.stop(t)
	replacement := fixture.New(t, f.key.Profile.Issuer)
	changed, err := os.ReadFile(replacement.PublicFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.auxiliary.PublicFile, changed, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	f.refresh(t, next.RefreshToken, http.StatusUnauthorized)
	changedLogin := f.login(t, "body")
	f.stop(t)
	if err := os.WriteFile(f.auxiliary.PublicFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	f.refresh(t, next.RefreshToken, http.StatusUnauthorized)
	f.refresh(t, changedLogin.RefreshToken, http.StatusUnauthorized)
	f.login(t, "body")
}

func TestE2EServerManagedRefreshPartialActivation(t *testing.T) {
	f := newManagedRootTLS(t)
	first := f.login(t, "body")
	originalGeneration := f.generation
	originalConfig := append([]byte(nil), f.config...)
	f.stop(t)
	// Open a fresh borrowed handle for the candidate, retaining an immutable view
	// of the currently live generation before the candidate changes any marker.
	firstStore, err := refreshsqlite.New(t.Context(), &f.databaseConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	oldView, err := firstStore.ActivateGeneration(t.Context(), originalGeneration)
	if err != nil {
		t.Fatal(err)
	}
	var candidate authcrunch.Config
	if json.Unmarshal(originalConfig, &candidate) != nil {
		t.Fatal("candidate snapshot failed")
	}
	refresh := candidate.AuthenticationPortals[0].RefreshTokens
	oldBinding := tokenrefresh.Binding{Portal: "selected", Origin: refresh.PublicOrigin, BasePath: refresh.BasePath, Transport: tokenrefresh.BodyTransport, Namespace: originalGeneration.Namespace, Generation: originalGeneration.ID}
	if err := oldView.ValidateSession(t.Context(), first.SessionID, oldBinding); err != nil {
		t.Fatal("old family was not live before candidate activation", err)
	}
	secondDescriptor, err := tokenrefresh.NewExternalStoreConfig("later", "probe", 1, 16, struct{ ID string }{"later"})
	if err != nil {
		t.Fatal(err)
	}
	secondStore := &rootRefreshStoreProbe{descriptor: secondDescriptor}
	raw, err := json.Marshal(candidate.AuthenticationPortals[0])
	if err != nil {
		t.Fatal(err)
	}
	var later authn.PortalConfig
	if json.Unmarshal(raw, &later) != nil {
		t.Fatal("second portal snapshot failed")
	}
	later.Name = "later"
	later.RefreshTokens.Store = "later"
	candidate.AuthenticationPortals = append(candidate.AuthenticationPortals, &later)
	candidate.ExternalRefreshStores = append(candidate.ExternalRefreshStores, secondDescriptor)
	recording := &recordingManagedStore{ManagedStore: firstStore}
	root, err := authcrunch.NewServerWithOptions(&candidate, zap.NewNop(), authcrunch.ServerOptions{AccessSigners: map[string]kms.AccessSigner{"access": f.key.Signer}, RefreshStores: map[string]tokenrefresh.ManagedStore{"durable": recording, "later": secondStore}})
	if root != nil {
		_ = root.Close()
	}
	if err == nil || root != nil || secondStore.activations != 1 || recording.generation.Namespace != originalGeneration.Namespace || recording.generation.ID == originalGeneration.ID {
		t.Fatal("fixture did not fail after first real store activation")
	}
	if err := firstStore.CheckReady(t.Context()); err != nil || secondStore.closes != 0 {
		t.Fatal("failed root closed borrowed managed handles")
	}
	// Whole-root construction is not a distributed transaction: the completed
	// first retirement cannot be rolled back or revive its prior live family.
	if err := oldView.ValidateSession(t.Context(), first.SessionID, oldBinding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("partial failure restored retired authority", err)
	}
	if err := firstStore.Close(); err != nil {
		t.Fatal(err)
	}
	f.config = originalConfig
	f.start(t)
	f.refresh(t, first.RefreshToken, http.StatusUnauthorized)
	f.login(t, "body") // old capacity-one family cannot strand the recovered root
}

// The reader holds a real SQLite SHARED lock before form completion. The writer
// can begin and stage issuance, but actual COMMIT fails; no invented backend
// error substitutes for the tested HTTP/store boundary.
func TestE2EServerManagedRefreshFormCommitUncertainty(t *testing.T) {
	f := newManagedRootTLS(t)
	// This case deliberately quarantines the borrowed store. Drain and close
	// it even when an assertion fails, before the normal healthy-store cleanup.
	t.Cleanup(func() {
		f.selectedRootTLS.stop(t)
		if f.database != nil {
			if err := f.database.Close(); err != nil {
				t.Error("quarantined refresh store cleanup failed", err)
			}
			f.database = nil
		}
	})
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	form := func(method, target string, values url.Values) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal("form request construction failed")
		}
		request.Header.Set("Accept", "text/html")
		request.Header.Set("Origin", f.server.URL)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		if method == http.MethodPost {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("form TLS request failed")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 128<<10))
		response.Body.Close()
		if readErr != nil || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatal("form response was not privately trusted and readable")
		}
		return response
	}
	start := form(http.MethodPost, f.server.URL+"/auth/login", url.Values{"username": {"alice"}, "realm": {"local"}})
	sandbox, err := start.Location()
	if start.StatusCode != http.StatusSeeOther || err != nil || sandbox.Scheme+"://"+sandbox.Host != f.server.URL || !strings.HasPrefix(sandbox.Path, "/auth/sandbox/") {
		t.Fatal("form login did not reach its checkpoint")
	}
	password := form(http.MethodPost, sandbox.String(), url.Values{"secret": {tests.TestPwd1}})
	if password.StatusCode != http.StatusSeeOther {
		t.Fatal("form password did not complete checkpoint")
	}
	readerDB, err := sql.Open("sqlite", f.databaseConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer readerDB.Close()
	readerDB.SetMaxOpenConns(1)
	reader, err := readerDB.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.QueryRowContext(t.Context(), "SELECT count(*) FROM refresh_families_v2").Scan(&count); err != nil {
		t.Fatal(err)
	}
	response := form(http.MethodGet, sandbox.String(), nil)
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Authorization") != "" || response.Header.Get("Location") != "" {
		t.Fatalf("uncertain form completion returned HTTP%d or published authority", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("uncertain form completion published a credential cookie")
		}
	}
	portalURL, _ := url.Parse(f.server.URL + "/auth/portal")
	for _, cookie := range client.Jar.Cookies(portalURL) {
		if cookie.Name == "WIRE_ACCESS" || cookie.Name == "AUTHP_REFRESH_TOKEN" || cookie.Name == "AUTHP_OIDC_SESSION_ID" {
			t.Fatal("uncertain form completion retained authentication authority")
		}
	}
	if err := f.database.CheckReady(t.Context()); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("attempted commit failure did not quarantine handle")
	}
	// The ordinary browser correlation cookie is not authentication authority.
	// The same browser cannot access protected content or reuse its consumed proof.
	if response := form(http.MethodGet, f.server.URL+"/protected", nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("failed form issuance authorized the browser")
	}
	if response := form(http.MethodGet, sandbox.String(), nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("failed form issuance retained reusable proof")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := readerDB.QueryRowContext(t.Context(), "SELECT count(*) FROM refresh_families_v2").Scan(&count); err != nil || count != 0 {
		t.Fatal("concrete busy-COMMIT rollback left an undelivered family", err)
	}
	// This fixture observes the concrete rollback; ordinary clients still may not
	// replay an uncertain exchange. Recovery replaces handles and authenticates.
	f.selectedRootTLS.stop(t)
	if err := f.database.Close(); err != nil {
		t.Fatal(err)
	}
	f.database = nil
	if err := readerDB.Close(); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	fresh := f.login(t, "body")
	f.refresh(t, fresh.RefreshToken, http.StatusOK)
}
