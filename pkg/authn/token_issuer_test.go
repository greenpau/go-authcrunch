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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// Unit tests stage a completed proof to isolate the issuer. The external TLS
// login tests establish that only actual checkpoint completion reaches it.
func completedIdentityProof(t *testing.T, f *refreshPortalFixture) (*user.User, *requests.Request) {
	t.Helper()
	p := f.portal
	var err error
	p.transformer, err = transformer.NewFactory([]*transformer.Config{{Matchers: []string{"exact match realm local"}, Actions: []string{"overwrite email alias@example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	rr := requests.NewRequest()
	if err := p.identifyUserRequest(rr, map[string]string{"username": tests.TestEmail1, "realm": "local"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/login", nil)
	proof, err := p.createSandboxUser(t.Context(), httptest.NewRecorder(), r, rr)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range proof.Checkpoints {
		c.Passed = true
	}
	return proof, rr
}

func TestSandboxCanonicalIdentity(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	proof, rr := completedIdentityProof(t, f)
	if proof.LoginUsername != tests.TestUser1 || proof.LoginEmail != tests.TestEmail1 || proof.Claims.Email != "alias@example.test" || proof.LoginEvidence != rr.Authentication {
		t.Fatal("sandbox did not retain backend identity separately from claims")
	}
	proof.Claims.Subject = "different-account"
	u, tokens, err := f.portal.issueSandboxTokens(t.Context(), httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/sandbox/id", nil), rr, proof)
	if err != nil || tokens != nil || u == nil || u.Claims.Subject != tests.TestUser1 || u.Claims.Email != "alias@example.test" {
		t.Fatal("access issuance trusted transformed sandbox identity")
	}
}

func TestSandboxAccessIdentityDenial(t *testing.T) {
	for _, change := range []string{"username", "email", "additional factor", "incomplete factor", "missing checkpoints"} {
		t.Run(change, func(t *testing.T) {
			f := newRefreshPortal(t, false, false)
			proof, rr := completedIdentityProof(t, f)
			current := identity.RefreshIdentity{Username: tests.TestUser1, Email: tests.TestEmail1, Roles: []string{"authp/user"}, Challenges: []string{"password"}}
			switch change {
			case "username":
				current.Username = "changed"
			case "email":
				current.Email = "changed@example.test"
			case "additional factor":
				current.Challenges = append(current.Challenges, "totp")
			case "incomplete factor":
				proof.Checkpoints[0].Passed = false
			case "missing checkpoints":
				proof.Checkpoints = nil
			}
			u, err := f.portal.issueSandboxAccessToken(t.Context(), httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth", nil), rr, proof, current)
			if !errors.Is(err, tokenrefresh.ErrDenied) || u != nil {
				t.Fatal("identity or checkpoint mismatch produced an access token")
			}
		})
	}
}

func TestSandboxAccessEvidenceDenial(t *testing.T) {
	for _, change := range []string{"credential revocation", "backend reload", "password reset", "recreated username", "wrong backend", "missing canonical username"} {
		t.Run(change, func(t *testing.T) {
			f := newRefreshPortal(t, false, false)
			proof, rr := completedIdentityProof(t, f)
			var err error
			switch change {
			case "credential revocation":
				err = f.store.RevokeUserSessions(t.Context(), proof.LoginEvidence.UserID)
			case "backend reload":
				err = f.store.Reload()
			case "password reset":
				_, err = f.store.ResetUserPassword(tests.TestUser1, tests.TestEmail1)
			case "recreated username":
				if err := f.store.DeleteUser(tests.TestUser1, tests.TestEmail1); err != nil {
					t.Fatal(err)
				}
				err = f.store.Request(operator.AddUser, &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1, Password: tests.TestPwd1}})
			case "wrong backend":
				proof.Authenticator.Name = "another-backend"
			case "missing canonical username":
				proof.LoginUsername = ""
			}
			if err != nil {
				t.Fatal("could not apply identity mutation")
			}
			u, tokens, err := f.portal.issueSandboxTokens(t.Context(), httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth", nil), rr, proof)
			if !errors.Is(err, tokenrefresh.ErrDenied) || u != nil || tokens != nil {
				t.Fatal("stale or misbound proof produced credentials")
			}
		})
	}
}

// Embedding the dispatch interface deliberately hides the optional transactional
// API, exercising the fallback contract for stores such as LDAP.
type identifyingOnlyStore struct{ ids.IdentityStore }

func TestSandboxLegacyIdentityStore(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	proof, rr := completedIdentityProof(t, f)
	f.portal.identityStores = []ids.IdentityStore{&identifyingOnlyStore{f.store}}
	proof.Claims.Subject = "another-account"
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth", nil)
	u, tokens, err := f.portal.issueSandboxTokens(t.Context(), r, rr, proof)
	if err != nil || tokens != nil || u == nil || u.Claims.Subject != tests.TestUser1 || u.Claims.Email != "alias@example.test" {
		t.Fatal("legacy identification did not use the canonical account")
	}
	proof.LoginEmail = "changed@example.test"
	if u, tokens, err := f.portal.issueSandboxTokens(t.Context(), r, rr, proof); !errors.Is(err, tokenrefresh.ErrDenied) || u != nil || tokens != nil {
		t.Fatal("legacy identity mismatch produced credentials")
	}
}
