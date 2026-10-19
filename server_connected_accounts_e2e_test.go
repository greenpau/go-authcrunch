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
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	attachmentparser "github.com/greenpau/go-authcrunch/pkg/identity/attachment/parser"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EServerDirectOAuthLocalIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if _, err := identity.NewDatabase(path); err != nil {
		t.Fatal(err)
	}
	attachment, err := attachmentparser.NewIdentityAttachmentConfigFromDirectives([]string{"attach to local identity store accounts"})
	if err != nil {
		t.Fatal(err)
	}
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) {
		c.State = persistentTestConfig(t)
		c.IdentityStores = []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local", Params: map[string]any{"path": path, "realm": "local"}}}
		c.IdentityProviders[0].Params["attachment"] = attachment
	})
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	var username string
	for _, u := range db.Users {
		if len(u.ExternalAccounts) == 1 {
			username = u.Username
			if u.ID == "alice" || u.ID == "" {
				t.Fatal("missing independent local identity")
			}
		}
	}
	if username == "" {
		t.Fatal("direct OAuth did not provision into configured store")
	}
	if err := db.DisableUser(&requests.Request{User: requests.User{Username: username}}); err != nil {
		t.Fatal(err)
	}
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 403)
	callback = f.callback(t, f.client, "/second/resource")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 401)
}

func TestE2EServerDirectOAuthMemoryIdentityRestart(t *testing.T) {
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) { c.State = persistentTestConfig(t) })
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 403)
}
