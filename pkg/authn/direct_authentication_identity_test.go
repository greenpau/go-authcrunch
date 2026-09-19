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
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestDirectAuthenticationIdentity(t *testing.T) {
	for _, name := range []string{"current", "explicit policy", "identification only", "changed username", "changed email", "revoked", "cancelled", "callback failure"} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshPortal(t, false, false)
			if name == "explicit policy" {
				if _, err := f.store.OverwriteUserAuthChallengeRules(tests.TestUser1, tests.TestEmail1, []string{"password"}); err != nil {
					t.Fatal(err)
				}
			}
			rr := &requests.Request{User: requests.User{Username: tests.TestUser1, Password: tests.TestPwd1}, Upstream: requests.Upstream{Realm: "local"}}
			if err := f.store.Request(operator.IdentifyUser, rr); err != nil {
				t.Fatal(err)
			}
			wantRoles := slices.Clone(rr.User.Roles)
			if name != "identification only" {
				if err := f.store.Request(operator.Authenticate, rr); err != nil {
					t.Fatal(err)
				}
			}
			rr.User.Roles, rr.User.AuthMethods, rr.User.Challenges = []string{"stale"}, []string{"u2f"}, []string{"totp"}
			rr.User.AuthChallengePolicy = name != "explicit policy"
			ctx := t.Context()
			switch name {
			case "changed username":
				rr.User.Username = "another-user"
			case "changed email":
				rr.User.Email = "another@example.test"
			case "revoked":
				if err := f.store.RevokeUserSessions(ctx, rr.Authentication.UserID); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel func()
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			callbackErr := errors.New("issuance rejected")
			called := false
			err := f.portal.withDirectAuthenticationIdentity(ctx, rr, func() error {
				called = true
				if !slices.Equal(rr.User.Roles, wantRoles) || !slices.Equal(rr.User.AuthMethods, []string{"password"}) || !slices.Equal(rr.User.Challenges, []string{"password"}) || rr.User.AuthChallengePolicy != (name == "explicit policy") {
					t.Fatal("issuance used stale identity attributes or policy")
				}
				if name == "callback failure" {
					return callbackErr
				}
				return nil
			})
			switch name {
			case "current", "explicit policy":
				if err != nil || !called {
					t.Fatal("current proof denied", err)
				}
			case "callback failure":
				if !called || !errors.Is(err, callbackErr) || rr.Response.Code != http.StatusInternalServerError {
					t.Fatal("callback error not preserved", err)
				}
			case "cancelled":
				if called || !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled request reached issuer", err)
				}
			default:
				if called || !errors.Is(err, identity.ErrRefreshIdentityDenied) || rr.Response.Code != http.StatusUnauthorized {
					t.Fatal("unverified or stale proof reached issuer", err)
				}
			}
		})
	}
}
