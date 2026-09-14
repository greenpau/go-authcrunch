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
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EServerPGPPublicKeyPersistence(t *testing.T) {
	f := newServerCompositionFixture(t, true)
	payload, err := os.ReadFile("testdata/gpg/linux_gpg_pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	request := func(kind, content string) compositionResponse {
		t.Helper()
		body, err := json.Marshal(map[string]string{"kind": kind, "content": content, "title": "Legacy PGP key", "description": "Compatibility test"})
		if err != nil {
			t.Fatal(err)
		}
		return f.request(t, http.MethodPost, "/api/profile", string(body), http.Header{"Content-Type": {"application/json"}, "Origin": {f.origin}})
	}
	unauthenticated := request("add_user_gpg_key", string(payload))
	compositionStatus(t, unauthenticated, http.StatusForbidden)
	f.login(t, "local", "alice")
	malformed := request("add_user_gpg_key", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA==\n-----END PGP PUBLIC KEY BLOCK-----")
	compositionStatus(t, malformed, http.StatusBadRequest)
	compositionStatus(t, request("add_user_gpg_key", string(payload)), http.StatusOK)
	compositionStatus(t, request("add_user_gpg_key", string(payload)), http.StatusBadRequest)
	check := func(response compositionResponse) {
		t.Helper()
		compositionStatus(t, response, http.StatusOK)
		var decoded struct {
			Entries []identity.PublicKey `json:"entries"`
		}
		if json.Unmarshal(response.body, &decoded) != nil || len(decoded.Entries) != 1 {
			t.Fatal("expected exactly one persisted public key")
		}
		key := decoded.Entries[0]
		if key.ID != "a040830f7fac5991" || key.Fingerprint != "4cca1eaf950cee4ab83976dca040830f7fac5991" || key.Type != "dsa" || key.Payload != strings.TrimSpace(string(payload)) {
			t.Fatal("persisted legacy PGP metadata changed")
		}
	}
	check(request("fetch_user_gpg_keys", ""))
	// A fresh database handle and fresh root runtime must read the same identity
	// data. No OpenPGP signing/decryption operation is involved in this workflow.
	db, err := identity.NewDatabase(f.usersFile)
	if err != nil {
		t.Fatal(err)
	}
	rr := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Usage: "gpg"}}
	if err := db.GetPublicKeys(rr); err != nil {
		t.Fatal(err)
	}
	if rr.Response.Payload.(*identity.PublicKeyBundle).Size() != 1 {
		t.Fatal("database reopen lost public key")
	}
	f.replace(t, false, "")
	f.login(t, "local", "alice")
	check(request("fetch_user_gpg_keys", ""))
	f.login(t, "local", "admin")
	response := request("fetch_user_gpg_keys", "")
	compositionStatus(t, response, http.StatusOK)
	var other struct {
		Entries []identity.PublicKey `json:"entries"`
	}
	if json.Unmarshal(response.body, &other) != nil || len(other.Entries) != 0 {
		t.Fatal("another identity received Alice's public-key inventory")
	}
}
