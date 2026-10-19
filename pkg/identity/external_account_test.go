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

package identity_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EExternalAccountTransactions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	account := identity.ExternalAccount{Kind: "oauth", Provider: "github", Issuer: "https://github.com", Subject: "123", Email: "alice@example.test"}
	const concurrency = 8
	ids := make(chan string, concurrency)
	var wg sync.WaitGroup
	for range concurrency {
		wg.Go(func() {
			other, err := identity.NewDatabase(path)
			if err != nil {
				t.Error(err)
				return
			}
			u, err := other.ResolveExternalAccount(ctx, account, true)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- u.Evidence.UserID
		})
	}
	wg.Wait()
	close(ids)
	id := ""
	for candidate := range ids {
		if id != "" && id != candidate {
			t.Fatal("concurrent provisioning created two identities")
		}
		id = candidate
	}
	source, err := db.ResolveExternalAccount(ctx, account, false)
	if err != nil {
		t.Fatal(err)
	}
	if source.Evidence.UserID != id || len(source.Identity.AuthMethods) != 0 || source.Identity.Email != "" {
		t.Fatal("unexpected provisioned identity")
	}
	add := &requests.Request{User: requests.User{Username: "alice", Email: account.Email, Password: tests.TestPwd1Hash(t), Roles: []string{"member"}}}
	if err := db.AddUser(add); err != nil {
		t.Fatal(err)
	}
	login := &requests.Request{User: requests.User{Username: "alice", Password: tests.TestPwd1}}
	if err := db.AuthenticateUser(login); err != nil {
		t.Fatal(err)
	}
	// Re-capture source after the admin mutation; a stale version cannot authorize a connection.
	source, err = db.ResolveExternalAccount(ctx, account, false)
	if err != nil {
		t.Fatal(err)
	}
	key := account
	key.Email = "untrusted@example.test"
	linked, err := db.ConnectExternalAccount(ctx, key, source.Evidence, login.Authentication)
	if err != nil {
		t.Fatal(err)
	}
	if linked.Evidence.UserID != login.Authentication.UserID || linked.Evidence.UserID == id {
		t.Fatal("connection did not select immutable local ID")
	}
	if linked.Account.Email != account.Email {
		t.Fatal("connection did not preserve the verified display metadata")
	}
	reopened, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	current, err := reopened.ResolveExternalAccount(ctx, key, false)
	if err != nil || current.Evidence.UserID != linked.Evidence.UserID {
		t.Fatal("connection did not survive reopening", err)
	}
	if current.Account != linked.Account {
		t.Fatal("reopened lookup did not return the persisted connection metadata")
	}
	if err := db.WithRefreshIdentity(ctx, source.Evidence, func(identity.RefreshIdentity) error { t.Fatal("old source proof accepted"); return nil }); err == nil {
		t.Fatal("moved source retained authority")
	}
	if _, err := db.ConnectExternalAccount(ctx, account, source.Evidence, login.Authentication); err == nil {
		t.Fatal("connection replay accepted")
	}
	otherAccount := account
	otherAccount.Provider = "second"
	second, err := reopened.ResolveExternalAccount(ctx, otherAccount, true)
	if err != nil {
		t.Fatal(err)
	}
	if second.Evidence.UserID == linked.Evidence.UserID {
		t.Fatal("email/provider collision connected automatically")
	}
	if err := reopened.AuthenticateUser(login); err != nil {
		t.Fatal(err)
	}
	connectedSecond, err := reopened.ConnectExternalAccount(ctx, otherAccount, second.Evidence, login.Authentication)
	if err != nil || connectedSecond.Evidence.UserID != linked.Evidence.UserID || len(connectedSecond.Identity.ExternalAccounts) != 2 {
		t.Fatal("multiple providers did not share a local identity", err)
	}
	// Corrupt duplicate keys must not silently choose a record when reloaded.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot identity.Database
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Users[len(snapshot.Users)-1].ExternalAccounts = []identity.ExternalAccount{account}
	data, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewDatabase(path); err == nil {
		t.Fatal("duplicate persisted connection accepted")
	}
}

func TestExternalAccountBoundaries(t *testing.T) {
	ctx := context.Background()
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	account := identity.ExternalAccount{Kind: "oauth", Provider: "oidc", Issuer: "https://issuer.test", Subject: "one"}
	if _, err := db.ResolveExternalAccount(ctx, account, false); err == nil {
		t.Fatal("unknown account accepted")
	}
	first, err := db.ResolveExternalAccount(ctx, account, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []identity.ExternalAccount{
		{Kind: "oauth", Provider: "other", Issuer: account.Issuer, Subject: account.Subject},
		{Kind: "saml", Provider: account.Provider, Issuer: account.Issuer, Subject: account.Subject},
		{Kind: "oauth", Provider: account.Provider, Issuer: "https://other.test", Subject: account.Subject},
		{Kind: "oauth", Provider: account.Provider, Issuer: account.Issuer, Subject: "ONE"},
	} {
		u, err := db.ResolveExternalAccount(ctx, changed, true)
		if err != nil || u.Evidence.UserID == first.Evidence.UserID {
			t.Fatal("identity namespace collapsed", err)
		}
	}
	// Returned data must not alias live records.
	first.Identity.Roles = append(first.Identity.Roles, "admin")
	repeat, err := db.ResolveExternalAccount(ctx, account, false)
	if err != nil || len(repeat.Identity.Roles) != 0 {
		t.Fatal("detached result mutated database", err)
	}
	invalid := account
	invalid.Subject = ""
	if _, err := db.ResolveExternalAccount(ctx, invalid, true); err == nil {
		t.Fatal("empty subject accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := db.ResolveExternalAccount(canceled, account, true); err == nil {
		t.Fatal("canceled lookup accepted")
	}
	if err := db.DisableUser(&requests.Request{User: requests.User{Username: repeat.Identity.Username}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ResolveExternalAccount(ctx, account, true); err == nil {
		t.Fatal("disabled account reprovisioned")
	}
}

func TestExternalAccountLookupMetadata(t *testing.T) {
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	account := identity.ExternalAccount{Kind: "oauth", Provider: "provider", Issuer: "https://issuer.test", Subject: "subject", Email: "original@example.test", Name: "Original"}
	created, err := db.ResolveExternalAccount(t.Context(), account, true)
	if err != nil {
		t.Fatal(err)
	}
	if created.Account.ConnectedAt.IsZero() {
		t.Fatal("provisioning omitted the connection time")
	}
	account.Email, account.Name = "changed@example.test", "Changed"
	account.ConnectedAt = time.Unix(1, 0)
	for _, create := range []bool{false, true} {
		resolved, err := db.ResolveExternalAccount(t.Context(), account, create)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Account != created.Account || len(resolved.Identity.ExternalAccounts) != 1 || resolved.Account != resolved.Identity.ExternalAccounts[0] {
			t.Fatal("lookup returned supplied metadata instead of the stored connection")
		}
	}
}

func TestExternalAccountConnectionEvidence(t *testing.T) {
	ctx := t.Context()
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	account := identity.ExternalAccount{Kind: "oauth", Provider: "provider", Issuer: "https://issuer.test", Subject: "subject"}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "member", Email: "member@example.test", Password: tests.TestPwd1Hash(t)}}); err != nil {
		t.Fatal(err)
	}
	login := &requests.Request{User: requests.User{Username: "member", Password: tests.TestPwd1}}
	if err := db.AuthenticateUser(login); err != nil {
		t.Fatal(err)
	}
	source, err := db.ResolveExternalAccount(ctx, account, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name   string
		modify func(*requests.AuthenticationEvidence)
	}{
		{"expired", func(p *requests.AuthenticationEvidence) { p.AuthenticatedAt = time.Now().Add(-6 * time.Minute).Unix() }},
		{"future", func(p *requests.AuthenticationEvidence) { p.AuthenticatedAt = time.Now().Add(time.Minute).Unix() }},
		{"missing time", func(p *requests.AuthenticationEvidence) { p.AuthenticatedAt = 0 }},
		{"wrong epoch", func(p *requests.AuthenticationEvidence) { p.BackendVersion = "wrong" }},
		{"revoked version", func(p *requests.AuthenticationEvidence) { p.CredentialVersion++ }},
		{"missing account", func(p *requests.AuthenticationEvidence) { p.UserID = "absent" }},
		{"API key", func(p *requests.AuthenticationEvidence) { p.Method = "api_key" }},
		{"key evidence", func(p *requests.AuthenticationEvidence) { p.APIKeyID = "key" }},
	} {
		for _, side := range []string{"source", "destination"} {
			t.Run(change.name+"/"+side, func(t *testing.T) {
				from, to := source.Evidence, login.Authentication
				if side == "source" {
					change.modify(&from)
				} else {
					change.modify(&to)
				}
				if _, err := db.ConnectExternalAccount(ctx, account, from, to); err == nil {
					t.Fatal("invalid proof connected account")
				}
				current, err := db.ResolveExternalAccount(ctx, account, false)
				if err != nil || current.Evidence.UserID != source.Evidence.UserID {
					t.Fatal("denial changed connection", err)
				}
			})
		}
	}
	if _, err := db.ConnectExternalAccount(ctx, account, source.Evidence, source.Evidence); err == nil {
		t.Fatal("self connection accepted")
	}
	// Only a disposable account may move. A factor makes it an established identity.
	if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: source.Identity.Username}, MfaToken: requests.MfaToken{Type: "totp", Comment: "factor", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true}}); err != nil {
		t.Fatal(err)
	}
	source, err = db.ResolveExternalAccount(ctx, account, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConnectExternalAccount(ctx, account, source.Evidence, login.Authentication); err == nil {
		t.Fatal("established identity consumed as shell")
	}
}

func TestExternalAccountDisableEnable(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		for _, kind := range []string{"external", "local", "external with local email"} {
			t.Run(storage+"/"+kind, func(t *testing.T) {
				path := ":memory:"
				if storage == "file" {
					path = filepath.Join(t.TempDir(), "users.json")
				}
				db, err := identity.NewDatabase(path)
				if err != nil {
					t.Fatal(err)
				}
				account := identity.ExternalAccount{Provider: "provider", Kind: "oauth", Issuer: "https://issuer.test", Subject: "subject", Email: "upstream@example.test"}
				var proof requests.AuthenticationEvidence
				selector := &requests.Request{User: requests.User{Username: "member", Email: "local@example.test"}}
				if kind == "external" {
					resolved, err := db.ResolveExternalAccount(t.Context(), account, true)
					if err != nil {
						t.Fatal(err)
					}
					proof = resolved.Evidence
					selector.User.Username, selector.User.Email = resolved.Identity.Username, ""
				} else {
					selector.User.Password = tests.TestPwd1Hash(t)
					if err := db.AddUser(selector); err != nil {
						t.Fatal(err)
					}
					if kind == "external with local email" {
						db.Users[0].ExternallyProvisioned = true
						if err := db.Save(); err != nil {
							t.Fatal(err)
						}
					}
					login := &requests.Request{User: requests.User{Username: selector.User.Username, Password: tests.TestPwd1}}
					if err := db.AuthenticateUser(login); err != nil {
						t.Fatal(err)
					}
					proof = login.Authentication
				}
				if err := db.DisableUser(selector); err != nil {
					t.Fatal(err)
				}
				wrong := *selector
				wrong.User.Email = account.Email
				if err := db.EnableUser(&wrong); err == nil {
					t.Fatal("upstream display email selected a local account")
				}
				wrong.User.Email = ""
				if kind != "external" {
					if err := db.EnableUser(&wrong); err == nil {
						t.Fatal("local email selector was bypassed")
					}
				}
				if err := db.EnableUser(selector); err != nil {
					t.Fatal("could not re-enable the same account", err)
				}
				if err := db.EnableUser(selector); err == nil {
					t.Fatal("already enabled account accepted")
				}
				if err := db.WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error {
					t.Fatal("disable/enable revived old authentication evidence")
					return nil
				}); err == nil {
					t.Fatal("old evidence was not revoked")
				}
				if storage == "file" {
					db, err = identity.NewDatabase(path)
					if err != nil {
						t.Fatal(err)
					}
				}
				if len(db.Users) != 1 || db.Users[0].ID != proof.UserID || db.Users[0].Disabled || db.Users[0].CredentialVersion != proof.CredentialVersion+2 {
					t.Fatal("enable did not preserve identity and advance credential generation")
				}
				if kind == "external" {
					resolved, err := db.ResolveExternalAccount(t.Context(), account, false)
					if err != nil || resolved.Evidence.UserID != proof.UserID || resolved.Identity.Email != "" {
						t.Fatal("external connection changed during disable/enable", err)
					}
				}
			})
		}
	}
}

func TestE2EExternalAccountFileRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	account := identity.ExternalAccount{Provider: "provider", Kind: "oauth", Issuer: "https://issuer.test", Subject: "subject"}
	first, err := db.ResolveExternalAccount(t.Context(), account, true)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeUserSessions(t.Context(), first.Evidence.UserID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	current, err := db.ResolveExternalAccount(t.Context(), account, false)
	if err != nil {
		t.Fatal(err)
	}
	if current.Evidence.UserID != first.Evidence.UserID || current.Evidence.BackendVersion == first.Evidence.BackendVersion {
		t.Fatal("file rollback resurrected the old identity epoch")
	}
	if err := db.WithRefreshIdentity(t.Context(), first.Evidence, func(identity.RefreshIdentity) error {
		t.Fatal("revoked proof accepted after external lookup")
		return nil
	}); err == nil {
		t.Fatal("rolled-back proof authorized")
	}
	if err := db.WithRefreshIdentity(t.Context(), current.Evidence, func(identity.RefreshIdentity) error { return nil }); err != nil {
		t.Fatal("fresh upstream login could not authenticate restored account", err)
	}
}
