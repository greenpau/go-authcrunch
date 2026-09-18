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
	"encoding/json"
	"os"
	"testing"
)

func TestProfileIdentitySnapshot(t *testing.T) {
	db, r := refreshTestDatabase(t)
	if db.Users[0].Profile != nil {
		t.Fatal("default identity fabricated personal attributes")
	}
	db.Users[0].Profile = &Profile{GivenName: "Test", PhoneNumber: "+1 202-555-0100", PhoneNumberVerified: new(false), Address: &Address{Country: "US"}}
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}
	err := db.WithRefreshIdentity(t.Context(), r.Authentication, func(current RefreshIdentity) error {
		if current.Profile == nil || current.Profile.GivenName != "Test" {
			t.Fatal("profile missing in identity transaction")
		}
		current.Profile.Address.Country = "Changed"
		*current.Profile.PhoneNumberVerified = true
		current.Profile.GivenName = "Changed"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	original := db.Users[0].Profile
	if original.GivenName != "Test" || original.Address.Country != "US" || *original.PhoneNumberVerified {
		t.Fatal("callback mutated persisted identity")
	}
	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db.GetPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewDatabase(db.GetPath())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Users[0].Profile.Address.Country != "US" || loaded.Users[0].Profile.PhoneNumberVerified == nil || *loaded.Users[0].Profile.PhoneNumberVerified {
		t.Fatal("profile lost on reload")
	}
}
