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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
)

func TestCredentialCacheKeyDoesNotRetainSecret(t *testing.T) {
	r := &authproxy.Request{Address: "192.0.2.1", Realm: "local", Secret: "reusable-secret"}
	first := credentialCacheKey("local", r)
	if strings.Contains(first, r.Secret) {
		t.Fatal("credential cache key contains reusable secret")
	}
	if first != credentialCacheKey("local", r) {
		t.Fatal("credential cache key is not deterministic")
	}
	if first == credentialCacheKey("remote", r) {
		t.Fatal("credential cache key does not separate authenticator kinds")
	}
	r.Address = "192.0.2.2"
	if first == credentialCacheKey("local", r) {
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
