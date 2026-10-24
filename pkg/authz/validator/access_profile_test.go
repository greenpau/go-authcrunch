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

package validator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func TestAccessProfileCacheAdmission(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	v, err := NewTokenValidator(f.CryptoConfig(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	list := acl.NewAccessList()
	list.SetLogger(zap.NewNop())
	if err := list.AddRules(t.Context(), []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}); err != nil {
		t.Fatal(err)
	}
	opts := options.NewTokenValidatorOptions()
	opts.ValidateBearerHeader = true
	if err := v.Configure(t.Context(), list, opts); err != nil {
		t.Fatal(err)
	}
	claims := f.Claims()
	claims["metadata"] = map[string]any{"department": "operations"}
	claims["acl"] = map[string]any{"paths": map[string]any{"/protected": true}}
	token := f.Token(t, claims)
	u, err := user.NewUser(claims)
	if err != nil {
		t.Fatal(err)
	}
	u.Token = token
	if err := v.CacheUser(u); err != nil {
		t.Fatal("valid signed cache entry rejected", err)
	}
	request := func(raw string) error {
		r := httptest.NewRequest(http.MethodGet, "https://resource.test/protected", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		_, err := v.Authorize(t.Context(), r, requests.NewAuthorizationRequest())
		return err
	}
	if err := request(token); err != nil {
		t.Fatal("positive cache control rejected", err)
	}
	for name, mutate := range map[string]func(*user.User){
		"nil_claims":       func(u *user.User) { u.Claims = nil },
		"subject":          func(u *user.User) { u.Claims.Subject = "forged" },
		"roles":            func(u *user.User) { u.Claims.Roles = []string{"authp/admin"} },
		"expiry":           func(u *user.User) { u.Claims.ExpiresAt++ },
		"issued_at":        func(u *user.User) { u.Claims.IssuedAt-- },
		"not_before":       func(u *user.User) { u.Claims.NotBefore-- },
		"metadata":         func(u *user.User) { u.Claims.Metadata["department"] = "administration" },
		"acl":              func(u *user.User) { u.Claims.AccessList.Paths["/admin"] = true },
		"data_roles":       func(u *user.User) { u.GetData()["roles"] = []string{"authp/admin"} },
		"data_acl":         func(u *user.User) { u.GetData()["acl"] = map[string]any{"paths": map[string]any{"/admin": true}} },
		"signed_map_roles": func(u *user.User) { u.AsMap()["roles"] = []string{"authp/admin"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := u.Clone()
			mutate(candidate)
			if err := v.CacheUser(candidate); err == nil {
				t.Fatal("divergent user view entered the signed-token cache")
			}
			if err := request(token); err != nil {
				t.Fatal("rejected mutation displaced the valid cache entry", err)
			}
		})
	}
	for _, source := range []string{"bearer", "basicauth", "apiauth"} {
		for _, raw := range []string{"not.a.token", token} {
			candidate := u.Clone()
			candidate.TokenSource = source
			candidate.Token = raw
			candidate.Claims.Subject = "forged"
			if err := v.CacheUser(candidate); err == nil {
				t.Fatal("forged cache entry accepted")
			}
		}
	}
	candidate := u.Clone()
	candidate.TokenSource = "basicauth"
	candidate.Token = credentialCachePrefix + "opaque-authoritative-credential-result"
	if err := v.CacheUser(candidate); err != nil {
		t.Fatal("credential namespace control failed", err)
	}
	if request(candidate.Token) == nil {
		t.Fatal("credential cache entry became bearer authority")
	}
	// Incoming alias metadata cannot change a cached signed claim.
	cached := v.cache.Get(token)
	cached.Claims.Subject = "modified"
	if err := request(token); err != nil {
		t.Fatal("cache clone was corrupted")
	}
	synctest.Test(t, func(t *testing.T) {
		c := f.Claims()
		c["exp"] = time.Now().Unix() + 1
		raw := f.Token(t, c)
		u, err := user.NewUser(c)
		if err != nil {
			t.Fatal(err)
		}
		u.Token = raw
		if err := v.CacheUser(u); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if request(raw) == nil {
			t.Fatal("cache bypassed exact expiry boundary")
		}
	})
}
