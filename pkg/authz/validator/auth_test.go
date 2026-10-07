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
	"context"
	"errors"
	"github.com/greenpau/go-authcrunch/pkg/authz/cache"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
)

func TestCredentialCacheKeyDoesNotRetainSecret(t *testing.T) {
	r := &authproxy.Request{Address: "192.0.2.1", Realm: "local", Secret: "reusable-secret"}
	first := credentialCacheKey("local", "basic", r)
	if strings.Contains(first, r.Secret) {
		t.Fatal("credential cache key contains reusable secret")
	}
	if first != credentialCacheKey("local", "basic", r) {
		t.Fatal("credential cache key is not deterministic")
	}
	if first == credentialCacheKey("remote", "basic", r) {
		t.Fatal("credential cache key does not separate authenticator kinds")
	}
	if first == credentialCacheKey("local", "api_key", r) {
		t.Fatal("credential cache aliases authentication methods")
	}
	r.Address = "192.0.2.2"
	if first == credentialCacheKey("local", "basic", r) {
		t.Fatal("credential cache key does not separate source addresses")
	}
}

func TestSplitAuthorizationEntriesPreservesQuotedCommas(t *testing.T) {
	got := splitAuthorizationEntries(`Digest username="a,b", Bearer token`)
	if len(got) != 2 || got[0] != `Digest username="a,b"` || got[1] != " Bearer token" {
		t.Fatalf("entries=%q", got)
	}
	got = splitAuthorizationEntries(`Digest username="unterminated, Bearer token`)
	if len(got) != 1 {
		t.Fatalf("malformed quoted value exposed a credential boundary: %q", got)
	}
}

type deadlineAuthenticator struct{ seen context.Context }

func (*deadlineAuthenticator) GetName() string                     { return "deadline" }
func (*deadlineAuthenticator) BasicAuth(*authproxy.Request) error  { panic("legacy path") }
func (*deadlineAuthenticator) APIKeyAuth(*authproxy.Request) error { panic("legacy path") }
func (a *deadlineAuthenticator) BasicAuthContext(ctx context.Context, r *authproxy.Request) error {
	a.seen = ctx
	r.Response.Payload = "verified"
	return nil
}
func (a *deadlineAuthenticator) APIKeyAuthContext(ctx context.Context, r *authproxy.Request) error {
	return a.BasicAuthContext(ctx, r)
}
func TestCredentialContextAndCacheCapability(t *testing.T) {
	a := &deadlineAuthenticator{}
	for _, basic := range []bool{false, true} {
		r := &authproxy.Request{}
		if err := authenticateCredential(t.Context(), a, r, basic); err != nil || a.seen != t.Context() || r.Response.Payload != "verified" {
			t.Fatal("context not propagated", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := authenticateCredential(ctx, a, &authproxy.Request{}, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	v := &TokenValidator{cache: cache.NewTokenCache(0)}
	defer v.cache.Close()
	usr, err := user.NewUser(map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	usr.Token = "credential"
	usr.CacheDisabled = true
	if err := v.CacheUser(usr); err != nil {
		t.Fatal(err)
	}
	if v.cache.Get(usr.Token) != nil {
		t.Fatal("fresh user cached")
	}
	cloned := usr.Clone()
	if !cloned.CacheDisabled {
		t.Fatal("clone lost cache policy")
	}
	usr.CacheDisabled = false
	if err := v.CacheUser(usr); err != nil {
		t.Fatal(err)
	}
	if v.credentialCacheUser(usr.Token, true) != nil || v.credentialCacheUser(usr.Token, false) == nil {
		t.Fatal("cache opt-out ignored")
	}
}
