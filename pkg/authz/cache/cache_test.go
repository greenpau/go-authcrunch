// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestTokenCache(t *testing.T) {
	c := NewTokenCache(100)
	d := NewTokenCache(0)

	testcases := []struct {
		name              string
		delay             int
		deletedByManager  bool
		emptyUser         bool
		emptyToken        bool
		emptyCache        bool
		emptyCacheEntries bool
		err               error
		shouldErr         bool
	}{
		{
			name: "valid token",
		},
		{
			name:      "get expired token",
			delay:     -900,
			shouldErr: true,
			err:       fmt.Errorf("token expired"),
		},
		{
			name:             "expired token deleted by cache manager",
			deletedByManager: true,
			shouldErr:        true,
			err:              fmt.Errorf("no user found"),
		},
		{
			name:      "nil user",
			emptyUser: true,
			shouldErr: true,
			err:       errors.ErrCacheNilUser,
		},
		{
			name:       "empty token",
			emptyToken: true,
			shouldErr:  true,
			err:        errors.ErrCacheEmptyToken,
		},
		{
			name:              "cache entries is nil",
			emptyCacheEntries: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			usr := testutils.NewTestUser()
			ks, err := testutils.NewTestCryptoKeyStore()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			err = ks.SignToken("access_token", "HS512", usr)
			if tc.emptyToken {
				usr.Token = ""
			}
			if tc.emptyUser {
				usr = nil
			}
			if usr != nil {
				switch {
				case tc.delay < 0:
					usr.Claims.ExpiresAt = time.Now().Add(time.Duration(tc.delay) * time.Second).Unix()
				case tc.deletedByManager:
					usr.Claims.ExpiresAt = time.Now().Add(time.Duration(-1000) * time.Second).Unix()
				}
			}
			err = c.Add(usr)
			d.Add(usr)
			if tc.delay == 0 && !tc.deletedByManager {
				if tests.EvalErrWithLog(t, err, "signed token", tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			if tc.emptyCacheEntries {
				c.mu.Lock()
				c.Entries = nil
				c.mu.Unlock()
			}

			time.Sleep(time.Millisecond * time.Duration(200))

			if tc.emptyCacheEntries {
				return
			}

			switch {
			case tc.delay < 0:
				if c.Get(usr.Token) == nil {
					err = fmt.Errorf("token expired")
				}
			case tc.deletedByManager:
				if c.Get(usr.Token) == nil {
					err = fmt.Errorf("no user found")
				}
			default:
				if c.Get(usr.Token) == nil {
					err = fmt.Errorf("token expired")
				}
			}

			if c.Get("foobar") != nil {
				err = fmt.Errorf("got user for invalid token")
			}

			if tests.EvalErrWithLog(t, err, "cache", tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestTokenCacheAddStoresIsolatedUser(t *testing.T) {
	c := NewTokenCache(0)
	usr := testutils.NewTestUser()
	ks, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ks.SignToken("access_token", "HS512", usr); err != nil {
		t.Fatalf("unexpected signing error: %v", err)
	}

	usr.BuildRequestIdentity("sub")
	usr.SetRequestHeaders(map[string]string{
		"X-Token-User-Email": usr.Claims.Email,
	})

	if err := c.Add(usr); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	usr.Claims.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	usr.Claims.Roles[0] = "admin"
	usr.GetRequestHeaders()["X-Token-User-Email"] = "mutated@example.com"
	usr.GetRequestIdentity()["id"] = "mutated@example.com"

	got := c.Get(usr.Token)
	if got == nil {
		t.Fatal("expected cached user to survive caller-owned mutation")
	}
	if got.Claims.ExpiresAt == usr.Claims.ExpiresAt {
		t.Fatal("expected cached user claims to be isolated from caller claims")
	}
	if got.Claims.Roles[0] == "admin" {
		t.Fatal("expected cached user roles to be isolated from caller roles")
	}
	if got.GetRequestHeaders()["X-Token-User-Email"] == "mutated@example.com" {
		t.Fatal("expected cached request headers to be isolated from caller headers")
	}
	if got.GetRequestIdentity()["id"] == "mutated@example.com" {
		t.Fatal("expected cached request identity to be isolated from caller identity")
	}
}

func TestTokenCacheGetReturnsIsolatedUser(t *testing.T) {
	c := NewTokenCache(0)
	usr := testutils.NewTestUser()
	ks, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ks.SignToken("access_token", "HS512", usr); err != nil {
		t.Fatalf("unexpected signing error: %v", err)
	}
	usr.BuildRequestIdentity("sub")

	if err := c.Add(usr); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	got := c.Get(usr.Token)
	if got == nil {
		t.Fatal("expected cached user")
	}
	got.Claims.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	got.GetRequestIdentity()["id"] = "mutated@example.com"

	got = c.Get(usr.Token)
	if got == nil {
		t.Fatal("expected cached user to survive returned-user mutation")
	}
	if got.Claims.ExpiresAt < time.Now().Unix() {
		t.Fatal("expected returned user claims to be isolated from cache")
	}
	if got.GetRequestIdentity()["id"] == "mutated@example.com" {
		t.Fatal("expected returned user identity to be isolated from cache")
	}
}
