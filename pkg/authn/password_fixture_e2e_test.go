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
	"errors"
	"net/http"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EFixturePasswordIsolation(t *testing.T) {
	first, store, _ := newLoginIdentityE2E(t, false, false, false, "")
	second, _, _ := newLoginIdentityE2E(t, false, false, false, "")

	// Both databases import the same immutable hashes, but a credential change
	// through a fresh database instance must affect only that database's portal.
	db, err := identity.NewDatabase(store.GetConfig()["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: "bob", Email: "bob@example.test", OldPassword: tests.TestPwd2, Password: tests.TestPwd1,
	}}); err != nil {
		t.Fatal("could not change fixture password")
	}
	for _, tc := range []struct {
		name     string
		portal   *oidcE2EFixture
		username string
		password string
		allowed  bool
	}{
		{"changed password", first, "bob", tests.TestPwd1, true},
		{"revoked password", first, "bob", tests.TestPwd2, false},
		{"independent database", second, "bob", tests.TestPwd2, true},
		{"other database password", second, "bob", tests.TestPwd1, false},
		{"first identity", second, "alice", tests.TestPwd1, true},
		{"other identity password", second, "alice", tests.TestPwd2, false},
		{"import is not plaintext", second, "alice", tests.TestPwd1Hash(t), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := authclient.NewClient(&authclient.Config{
				BaseURL: tc.portal.issuer, Realm: "local", Username: tc.username, Password: tc.password,
			}, authclient.Options{HTTPClient: tc.portal.client})
			if err != nil {
				t.Fatal("could not configure password fixture client")
			}
			credentials, err := client.Authenticate(t.Context())
			if tc.allowed {
				if err != nil || credentials == nil || credentials.AccessToken == "" {
					t.Fatal("current plaintext password did not authenticate")
				}
			} else {
				var status *authclient.HTTPError
				if credentials != nil || !errors.As(err, &status) || status.StatusCode != http.StatusUnauthorized {
					t.Fatal("invalid password did not return HTTP 401 without credentials")
				}
			}
		})
	}
}
