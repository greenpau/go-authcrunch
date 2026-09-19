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

package identity

import (
	"errors"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAPIKeyAuthenticationEvidence(t *testing.T) {
	db, authenticated := refreshTestDatabase(t)
	const secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	key := &requests.Request{User: authenticated.User, Key: requests.Key{Payload: secret, Usage: "api", Comment: "evidence regression"}}
	if err := db.AddAPIKey(key); err != nil {
		t.Fatal(err)
	}
	lookup := &requests.Request{Key: requests.Key{Payload: secret}}
	if err := db.LookupAPIKey(lookup); err != nil {
		t.Fatal(err)
	}
	proof := lookup.Authentication
	if proof.UserID != authenticated.Authentication.UserID || proof.BackendVersion == "" || proof.AuthenticatedAt == 0 || proof.Method != "api_key" || proof.APIKeyID == "" || proof.APIKeyID != db.Users[0].APIKeys[0].ID {
		t.Fatal("key verification did not capture bound evidence")
	}
	if err := db.WithRefreshIdentity(t.Context(), proof, func(current RefreshIdentity) error {
		if current.Username != authenticated.User.Username || current.AuthChallengePolicy {
			t.Fatal("incorrect current identity")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "another-key"} {
		invalid := proof
		invalid.APIKeyID = id
		if err := db.WithRefreshIdentity(t.Context(), invalid, func(RefreshIdentity) error {
			t.Fatal("unbound key reached issuer")
			return nil
		}); !errors.Is(err, ErrRefreshIdentityDenied) {
			t.Fatal("missing or different key ID accepted", err)
		}
	}
	for _, flag := range []string{"disabled", "expired"} {
		for _, active := range []bool{false, true} {
			db.mu.Lock()
			if flag == "disabled" {
				db.Users[0].APIKeys[0].Disabled = !active
			} else {
				db.Users[0].APIKeys[0].Expired = !active
			}
			err := db.commit()
			db.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			called := false
			err = db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error { called = true; return nil })
			if called != active || (err == nil) != active || (!active && !errors.Is(err, ErrRefreshIdentityDenied)) {
				t.Fatalf("%s key proof revalidation, active=%t: %v", flag, active, err)
			}
		}
	}
	for _, payload := range []string{"", "short", secret[:63] + "C"} {
		lookup.Key.Payload = payload
		lookup.Authentication = proof
		if err := db.LookupAPIKey(lookup); err == nil || lookup.Authentication != (requests.AuthenticationEvidence{}) {
			t.Fatal("failed lookup retained authentication evidence")
		}
	}
	key.Key.ID = db.Users[0].APIKeys[0].ID
	if err := db.DeleteAPIKey(key); err != nil {
		t.Fatal(err)
	}
	if err := db.WithRefreshIdentity(t.Context(), authenticated.Authentication, func(RefreshIdentity) error { return nil }); err != nil {
		t.Fatal("key deletion invalidated unrelated password evidence", err)
	}
	if err := db.WithRefreshIdentity(t.Context(), proof, func(RefreshIdentity) error {
		t.Fatal("deleted API key reached issuer")
		return nil
	}); !errors.Is(err, ErrRefreshIdentityDenied) {
		t.Fatal("key deletion failed to revoke captured proof", err)
	}
	lookup.Key.Payload, lookup.Authentication = secret, proof
	if err := db.LookupAPIKey(lookup); err == nil || lookup.Authentication != (requests.AuthenticationEvidence{}) {
		t.Fatal("deleted key retained authentication evidence")
	}
}
