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

package registry

import (
	"strings"
	"testing"
)

func TestRegistrationCacheOwnsDestination(t *testing.T) {
	cache := NewRegistrationCache()
	id := strings.Repeat("a", 64)
	entry := map[string]string{"username": "alice", "email": "alice@example.test", "password": "synthetic", "return_url": "https://app.test/first"}
	if err := cache.Add(id, entry); err != nil {
		t.Fatal(err)
	}
	entry["return_url"] = "https://app.test/other"
	first, err := cache.Get(id)
	if err != nil || first["return_url"] != "https://app.test/first" {
		t.Fatal("caller mutated pending destination", err)
	}
	first["return_url"] = "https://app.test/replaced"
	second, err := cache.Get(id)
	if err != nil || second["return_url"] != "https://app.test/first" {
		t.Fatal("read exposed mutable pending destination", err)
	}
	entry["username"], entry["email"] = "bob", "bob@example.test"
	if err := cache.Add(id, entry); err == nil {
		t.Fatal("registration ID replaced")
	}
}
