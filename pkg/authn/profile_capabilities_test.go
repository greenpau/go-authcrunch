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

package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type mutationFailureTestStore struct {
	ids.IdentityStore
	err error
}

func (s *mutationFailureTestStore) AddUserRoles(string, string, []string) (map[string]any, error) {
	return nil, s.err
}

func TestAPIMutationBackendErrors(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	backend := &mutationFailureTestStore{IdentityStore: f.store}
	f.portal.identityStores = []ids.IdentityStore{backend}
	for _, tc := range []struct {
		name, code string
		err        error
		status     int
	}{
		{"invalid", "operation_failed", errors.New("private backend detail"), http.StatusBadRequest},
		{"unavailable", "storage_unavailable", sqlitedb.ErrUnavailable, http.StatusServiceUnavailable},
		{"deadline", "storage_unavailable", context.DeadlineExceeded, http.StatusServiceUnavailable},
		{"canceled", "storage_unavailable", context.Canceled, http.StatusServiceUnavailable},
		{"wrapped_deadline", "storage_unavailable", errors.Join(errors.New("private backend detail"), context.DeadlineExceeded), http.StatusServiceUnavailable},
		{"uncertain_deadline", "commit_uncertain", errors.Join(sqlitedb.ErrCommitUncertain, context.DeadlineExceeded), http.StatusServiceUnavailable},
	} {
		for _, endpoint := range []string{"profile", "admin"} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				rr := requests.NewRequest()
				want := tc.status
				var err error
				if endpoint == "profile" {
					err = profileBackendError(w, rr, map[string]any{}, tc.err, http.StatusBadRequest)
				} else {
					backend.err = tc.err
					body := `{"realm":"` + f.store.GetRealm() + `","operation":"add_roles","user":{"username":"alice","email":"alice@example.test","roles":["extra"]}}`
					r := httptest.NewRequest(http.MethodPost, "/api/server/user", strings.NewReader(body))
					r.Header.Set("Content-Type", "application/json")
					err = f.portal.handleAPICrudUser(t.Context(), w, r, rr, nil)
					want = http.StatusOK // Preserve the legacy admin failure envelope.
				}
				var result map[string]any
				if err != nil || w.Code != want || json.Unmarshal(w.Body.Bytes(), &result) != nil {
					t.Fatalf("%s error response HTTP %d, want %d", endpoint, w.Code, want)
				}
				if result["code"] != tc.code || result["entry"] != nil || strings.Contains(w.Body.String(), "private backend detail") {
					t.Errorf("%s backend error code %v, want %s without backend details or success", endpoint, result["code"], tc.code)
				}
				if endpoint == "admin" && result["status"] != "failure" {
					t.Error("admin failure published success")
				}
			})
		}
	}
}

type profileMetadataTestStore struct {
	ids.IdentityStore
	passwordOnly bool
}

func (s *profileMetadataTestStore) GetCapabilities() identity.StoreCapabilities {
	if s.passwordOnly {
		return identity.StoreCapabilities{PasswordChange: true}
	}
	return identity.StoreCapabilities{ProfileRead: true}
}

type profileBoundMetadataTestStore struct {
	*profileMetadataTestStore
	ids.IdentityRequestStore
}

func TestProfileCapabilitiesEmptyOperations(t *testing.T) {
	declared := &profileMetadataTestStore{}
	for _, backend := range []ids.IdentityStore{declared, &profileIdentityStore{IdentityStore: declared}} {
		caps, ok := profileStoreCapabilities(backend)
		if !ok || !caps.ProfileRead || caps.AdminOperations == nil || len(caps.AdminOperations) != 0 {
			t.Error("partial provider did not retain an empty operations array")
		}
	}
	if declared.GetCapabilities().AdminOperations != nil {
		t.Fatal("metadata read mutated the provider")
	}
	if _, ok := profileStoreCapabilities(&profileIdentityStore{IdentityStore: &profileIdentityTestStore{}}); ok {
		t.Fatal("adapter manufactured a capability declaration")
	}
}

func TestProfileCapabilityRequiresBoundOperations(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	p := f.portal
	u, err := user.NewUser(map[string]any{"sub": "alice", "roles": []string{"authp/user"}, "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	u.Claims.ID, u.Token = strings.Repeat("a", 40), "synthetic-capability-unit-token"
	u.Authenticator = user.Authenticator{Name: f.store.GetName(), Realm: f.store.GetRealm(), Method: f.store.GetKind()}
	if err := p.sessions.Add(u.Claims.ID, u); err != nil {
		t.Fatal(err)
	}
	metadata := &profileMetadataTestStore{IdentityStore: f.store}
	for _, tc := range []struct{ bound, passwordOnly bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		bound := tc.bound
		metadata.passwordOnly = tc.passwordOnly
		var backend ids.IdentityStore = metadata
		if bound {
			backend = &profileBoundMetadataTestStore{profileMetadataTestStore: metadata, IdentityRequestStore: f.store}
		}
		p.identityStores = []ids.IdentityStore{backend}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://auth.example.test/api/capabilities", nil)
		rr := requests.NewRequest()
		rr.Response.Authenticated = true
		if err := p.handleAPICapabilities(t.Context(), w, r, rr, u); err != nil {
			t.Fatal(err)
		}
		var result struct{ Profile FeatureAvailability }
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("invalid capability response")
		}
		if !result.Profile.Enabled || result.Profile.Supported != bound || result.Profile.Allowed != bound {
			t.Errorf("profile availability disagrees with bound operation interface: bound=%t", bound)
		}
	}
}

func TestProfileCapabilitiesRejectUnknownOperations(t *testing.T) {
	all := identity.StoreCapabilities{ProfileRead: true, PasswordChange: true, APIKeys: true, PublicKeys: true, MFA: true, AuthenticationFlows: true}
	for _, operation := range []string{"", "unknown", "fetch_user_future_credentials"} {
		if profileOperationSupported(all, operation) {
			t.Errorf("unknown operation %q inherited a credential capability", operation)
		}
	}
	// A registered MFA operation still works with its own capability, while
	// unrelated password support must not grant factor enrollment.
	if !profileOperationSupported(identity.StoreCapabilities{MFA: true}, "add_user_u2f_token") ||
		profileOperationSupported(identity.StoreCapabilities{PasswordChange: true}, "add_user_u2f_token") {
		t.Fatal("factor enrollment did not require its own capability")
	}
}

func TestAPIWithoutConfiguration(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	token := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
	p.config.API = nil
	for _, target := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/api/capabilities/", http.StatusBadRequest},
		{"GET", "/api/%63apabilities", http.StatusBadRequest},
		{"GET", "/api/unknown", http.StatusBadRequest},
		{"GET", "/api/server/metadata", http.StatusBadRequest},
		{"POST", "/api/server/user", http.StatusBadRequest},
		{"POST", "/api/profile", http.StatusBadRequest},
		{"GET", "/api/server/private_keys", http.StatusNotFound},
	} {
		for _, principal := range []struct{ name, token string }{{"admin", token}, {"anonymous", ""}} {
			t.Run(principal.name+"/"+target.method+target.path, func(t *testing.T) {
				defer func() {
					if recover() != nil {
						t.Error("omitted API configuration caused a request panic")
					}
				}()
				response := privateKeysRequest(t, p, target.method, "/xauth"+target.path, principal.token)
				if response.Code != target.status {
					t.Fatalf("HTTP %d, want %d", response.Code, target.status)
				}
			})
		}
	}
}
