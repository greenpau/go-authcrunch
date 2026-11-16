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
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestIdentityProfileBindingAndPassword(t *testing.T) {
	s, cfg := fixture(t)
	provision(t, s)
	proof := authenticate(t, s, testPassword)
	request := func() *requests.Request {
		return &requests.Request{Authentication: proof, Upstream: requests.Upstream{Realm: "staff"}, User: requests.User{Username: "alice", Email: "alice@example.test"}}
	}
	for _, mutate := range []func(*requests.Request){
		func(r *requests.Request) { r.Authentication.UserID = "other" },
		func(r *requests.Request) { r.Authentication.BackendVersion = "old" },
		func(r *requests.Request) { r.Authentication.CredentialVersion++ },
		func(r *requests.Request) { r.User.Username = "other" },
		func(r *requests.Request) { r.User.Email = "other@example.test" },
		func(r *requests.Request) { r.Upstream.Realm = "other" },
	} {
		r := request()
		mutate(r)
		r.Response.Payload = "stale"
		r.Response.Authenticated = true
		if err := s.RequestWithIdentity(operator.GetUser, r); !errors.Is(err, identity.ErrIdentityRequestDenied) || r.Response.Payload != nil || r.Response.Authenticated {
			t.Fatal("invalid proof retained authority", err)
		}
	}
	r := request()
	if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
		t.Fatal(err)
	}
	u := r.Response.Payload.(*identity.User)
	if u.ID != proof.UserID || u.EmailAddress.Address != "alice@example.test" || u.Name.GetFullName() != "Alice" || len(u.Passwords) != 0 {
		t.Fatal("incorrect own-account projection")
	}
	u.Roles[0].Name = "mutated"
	r = request()
	if err := s.RequestWithIdentity(operator.GetUser, r); err != nil || r.Response.Payload.(*identity.User).Roles[0].Name != "viewer" {
		t.Fatal("profile result aliases store", err)
	}
	for _, candidate := range []string{"bcrypt:10:reserved-import", "argon2:reserved-import", "short"} {
		r := request()
		r.User.OldPassword = testPassword
		r.User.Password = candidate
		if err := s.RequestWithIdentity(operator.ChangePassword, r); !errors.Is(err, ErrInvalid) || r.Response.Payload != nil {
			t.Fatal("invalid password accepted", err)
		}
	}
	r = request()
	r.User.OldPassword = "incorrect"
	r.User.Password = "Replacement-password-2026!"
	if err := s.RequestWithIdentity(operator.ChangePassword, r); !errors.Is(err, ErrInvalid) {
		t.Fatal("incorrect old password accepted", err)
	}
	if err := s.RequestWithIdentity(operator.GetAPIKeys, request()); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	other, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.RequestWithIdentity(operator.GetUser, request()); !errors.Is(err, identity.ErrIdentityRequestDenied) {
		t.Fatal("foreign epoch accepted", err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	r = request()
	r.User.OldPassword = testPassword
	r.User.Password = "Replacement-password-2026!"
	if err := s.RequestWithIdentity(operator.ChangePassword, r); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestWithIdentity(operator.GetUser, request()); !errors.Is(err, identity.ErrIdentityRequestDenied) {
		t.Fatal("changed password retained profile proof", err)
	}
	old := &requests.Request{User: requests.User{Username: "alice", Password: testPassword}}
	if err := s.Request(operator.Authenticate, old); !errors.Is(err, ErrDenied) {
		t.Fatal("old password accepted", err)
	}
	fresh := authenticate(t, other, "Replacement-password-2026!")
	if fresh.UserID != proof.UserID || fresh.CredentialVersion <= proof.CredentialVersion {
		t.Fatal("password changed ownership or retained generation")
	}
}

func TestIdentityProfileInvalidStoredPassword(t *testing.T) {
	s, _ := fixture(t)
	provision(t, s)
	proof := authenticate(t, s, testPassword)
	var original string
	if err := s.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT password FROM accounts WHERE id=?", proof.UserID).Scan(&original)
	}); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"malformed":        "invalid-stored-verifier",
		"untrusted_cost":   strings.Replace(original, "$10$", "$31$", 1),
		"invalid_encoding": original[:7] + "!" + original[8:], // Keep the valid cost header; corrupt the salt encoding.
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, "UPDATE accounts SET password=? WHERE id=?", invalid, proof.UserID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			r := &requests.Request{Authentication: proof, User: requests.User{Username: "alice", Email: "alice@example.test", OldPassword: testPassword, Password: "Replacement-password-2026!"}}
			if err := s.RequestWithIdentity(operator.ChangePassword, r); !errors.Is(err, ErrUnavailable) || r.Response.Code == 200 || r.Response.Payload != nil {
				t.Error("invalid stored verifier was not a storage failure")
			}
			if err := s.db.Read(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
				var hash string
				var version uint64
				if err := tx.QueryRowContext(ctx, "SELECT password,version FROM accounts WHERE id=?", proof.UserID).Scan(&hash, &version); err != nil {
					return err
				}
				if hash != invalid || version != proof.CredentialVersion {
					t.Error("failed profile mutation changed the stored credentials")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := s.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE accounts SET password=? WHERE id=?", original, proof.UserID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if fresh := authenticate(t, s, testPassword); fresh.UserID != proof.UserID || fresh.CredentialVersion != proof.CredentialVersion {
		t.Fatal("rejected mutations changed the account identity or generation")
	}
}

func TestIdentityProfileRevocationAndCancellation(t *testing.T) {
	for _, mutation := range []string{"roles", "disabled", "deleted", "recreated", "closed"} {
		t.Run(mutation, func(t *testing.T) {
			s, cfg := fixture(t)
			a, _, _ := provision(t, s)
			proof := authenticate(t, s, testPassword)
			other, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			r := &requests.Request{Authentication: proof, User: requests.User{Username: a.Username, Email: a.Email}}
			if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "roles":
				_, err = other.AddUserRoles(a.Username, a.Email, []string{"new"})
			case "disabled":
				err = other.DisableUser(a.Username, a.Email)
			case "deleted", "recreated":
				err = other.DeleteUser(a.Username, a.Email)
				if err == nil && mutation == "recreated" {
					_, err = other.Create(t.Context(), a, testPassword)
				}
			case "closed":
				err = s.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			r.User.OldPassword = testPassword
			r.User.Password = "Must-not-be-installed!"
			err = s.RequestWithIdentity(operator.ChangePassword, r)
			want := identity.ErrIdentityRequestDenied
			if mutation == "closed" {
				want = ErrUnavailable
			}
			if !errors.Is(err, want) || r.Response.Payload != nil || r.Response.Code == 200 {
				t.Fatal("stale operation escaped", err)
			}
		})
	}
	s, _ := fixture(t)
	provision(t, s)
	proof := authenticate(t, s, testPassword)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://example.test", nil)
	r := &requests.Request{Authentication: proof, Upstream: requests.Upstream{Request: req}, User: requests.User{Username: "alice", Email: "alice@example.test"}}
	if err := s.RequestWithIdentity(operator.GetUser, r); !errors.Is(err, context.Canceled) || r.Response.Payload != nil {
		t.Fatal("canceled request returned data", err)
	}
}

func TestIdentityAtomicAddRolesAndMetadata(t *testing.T) {
	s, cfg := fixture(t)
	rows, err := s.GetUsersMetadata("")
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("empty list must be an array", err)
	}
	if _, err := s.GetUsersMetadata("unimplemented-filter"); !errors.Is(err, ErrUnsupported) {
		t.Fatal("ignored query", err)
	}
	a, _, _ := provision(t, s)
	other, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for i, st := range []*Store{s, other} {
		wg.Go(func() {
			_, err := st.AddUserRoles(a.Username, a.Email, []string{[]string{"one", "two"}[i]})
			failures <- err
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	proof := authenticate(t, s, testPassword)
	r := &requests.Request{Authentication: proof, User: requests.User{Username: a.Username, Email: a.Email}}
	if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
		t.Fatal(err)
	}
	u := r.Response.Payload.(*identity.User)
	roles := []string{}
	for _, role := range u.Roles {
		roles = append(roles, role.String())
	}
	for _, role := range []string{"viewer", "one", "two"} {
		if !slices.Contains(roles, role) {
			t.Fatal("lost concurrent role addition")
		}
	}
	if _, err := s.AddUserRoles(a.Username, a.Email, []string{"one", "two"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
		t.Fatal("idempotent retry revoked proof", err)
	}
	if _, err := s.AddUserRoles(a.Username, "wrong@example.test", []string{"admin"}); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong selector accepted", err)
	}
	data, err := s.FetchUserData(a.Username, a.Email)
	if err != nil {
		t.Fatal(err)
	}
	if data["name"].(*identity.Name).GetFullName() != a.Name || data["email_address"].(*identity.EmailAddress).Address != a.Email {
		t.Fatal("incorrect structured metadata")
	}
	encoded, _ := json.Marshal(data)
	var wire map[string]any
	if json.Unmarshal(encoded, &wire) != nil {
		t.Fatal("invalid wire record")
	}
	for _, key := range []string{"passwords", "password", "api_keys", "mfa_tokens", "public_keys", "created", "last_modified"} {
		if _, ok := wire[key]; ok {
			t.Fatal("invented or secret metadata field", key)
		}
	}
	for _, invalid := range [][]string{nil, {""}, {" leading-space"}, make([]string, 33)} {
		if _, err := s.AddUserRoles(a.Username, a.Email, invalid); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid role addition accepted", err)
		}
	}
	if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
		t.Fatal("failed role addition revoked current proof", err)
	}
	caps := s.GetCapabilities()
	caps.AdminOperations[0] = "changed"
	if s.GetCapabilities().AdminOperations[0] != "info" {
		t.Fatal("aliased capabilities")
	}
}

func TestIdentityProfileCommitFailure(t *testing.T) {
	s, cfg := fixture(t)
	provision(t, s)
	proof := authenticate(t, s, testPassword)
	// A real independent reader permits BEGIN IMMEDIATE and the update, but
	// prevents the final exclusive lock. COMMIT must not be retried or acknowledged.
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
	r := &requests.Request{Authentication: proof, User: requests.User{Username: "alice", Email: "alice@example.test", OldPassword: testPassword, Password: "Uncommitted-password-2026!"}}
	if err := s.RequestWithIdentity(operator.ChangePassword, r); !errors.Is(err, ErrCommitUncertain) || r.Response.Code == 200 || r.Response.Payload != nil {
		t.Fatal("uncertain mutation published success", err)
	}
	tx.Rollback()
	reopened, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	authenticate(t, reopened, testPassword)
}

func TestIdentityProfileRoleProjection(t *testing.T) {
	s, _ := fixture(t)
	provision(t, s)
	roles := []string{"authp/user", "/reader", "team/", "/", "team/nested/reader"}
	if _, err := s.OverwriteUserRoles("alice", "alice@example.test", roles); err != nil {
		t.Fatal(err)
	}
	data, err := s.FetchUserData("alice", "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	projected := data["roles"].([]*identity.Role)
	for i, role := range projected {
		if role.String() != roles[i] {
			t.Fatal("admin projection changed a stored role")
		}
	}
}

func TestIdentityRoleEncodingBound(t *testing.T) {
	// HTML escapes expand to six JSON bytes. Per-role and element-count bounds
	// alone must not allow a record larger than the reader's durable limit.
	roles := make([]string, 12)
	for i := range roles {
		roles[i] = strings.Repeat("<", 126) + fmt.Sprintf("%02d", i)
	}
	for _, operation := range []string{"create", "enroll", "add", "overwrite"} {
		t.Run(operation, func(t *testing.T) {
			s, _ := fixture(t)
			a, _, hash := provision(t, s)
			proof := authenticate(t, s, testPassword)
			var result map[string]any
			var err error
			switch operation {
			case "create", "enroll":
				invalid := &Account{Username: "invalid", Email: "invalid@example.test", Roles: roles}
				if operation == "create" {
					result, err = s.Create(t.Context(), invalid, testPassword)
				} else {
					result, err = s.CreateEnrollment(t.Context(), "00000000-0000-4000-8000-000000000001", invalid, hash)
				}
			case "add":
				result, err = s.AddUserRoles(a.Username, a.Email, roles)
			case "overwrite":
				result, err = s.OverwriteUserRoles(a.Username, a.Email, roles)
			}
			if !errors.Is(err, ErrInvalid) || result != nil {
				t.Errorf("oversized role encoding was not rejected atomically: %v", err)
			}
			r := &requests.Request{Authentication: proof, User: requests.User{Username: a.Username, Email: a.Email}}
			if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
				t.Fatal("rejected roles made the account unreadable or revoked proof", err)
			}
			rows, err := s.GetUsersMetadata("")
			if err != nil || len(rows) != 1 {
				t.Fatal("invalid roles changed the account inventory", err)
			}
			// The same character class remains supported when its encoded result
			// fits; do not solve the bound by changing the role-name alphabet.
			if _, err := s.AddUserRoles(a.Username, a.Email, roles[:8]); err != nil {
				t.Fatal("bounded escaped roles were rejected", err)
			}
			fresh := authenticate(t, s, testPassword)
			if fresh.UserID != proof.UserID || fresh.CredentialVersion <= proof.CredentialVersion {
				t.Fatal("accepted roles changed identity or retained stale evidence")
			}
			// The small incoming batch fits by itself, but its merged result does
			// not. The transaction must validate the complete stored collection.
			if result, err := s.AddUserRoles(a.Username, a.Email, roles[8:]); !errors.Is(err, ErrInvalid) || result != nil {
				t.Fatal("cumulative role encoding escaped the storage bound", err)
			}
			r.Authentication = fresh
			if err := s.RequestWithIdentity(operator.GetUser, r); err != nil {
				t.Fatal("rejected cumulative roles changed valid login evidence", err)
			}
		})
	}
}

// The admin API promises a complete bounded collection, not a silently
// truncated page. Populate current-schema rows directly to isolate that limit.
func TestIdentityMetadataCompleteListBound(t *testing.T) {
	s, _ := fixture(t)
	insert := func(first, last int) {
		t.Helper()
		if err := s.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `WITH RECURSIVE numbers(n) AS (
SELECT ? UNION ALL SELECT n+1 FROM numbers WHERE n < ?)
INSERT INTO accounts (id,realm,username,email,name,roles,password,version,enabled,enrollment)
SELECT printf('00000000-0000-4000-8000-%012d',n), 'staff', printf('user%05d',n),
printf('user%05d@example.test',n), '', ?, ?, 1, 1, printf('enrollment-%d',n) FROM numbers`, first, last, []byte(`["viewer"]`), dummyHash)
			return err
		}); err != nil {
			t.Fatal("cannot populate bounded account listing", err)
		}
	}
	insert(1, 10000)
	rows, err := s.GetUsersMetadata("all")
	if err != nil || len(rows) != 10000 || rows[0]["username"] != "user00001" || rows[9999]["username"] != "user10000" {
		t.Fatal("bounded list was incomplete or unsorted", err)
	}
	insert(10001, 10001)
	if rows, err := s.GetUsersMetadata("all"); !errors.Is(err, ErrUnavailable) || rows != nil {
		t.Fatal("oversized realm published a partial collection", err)
	}
}
