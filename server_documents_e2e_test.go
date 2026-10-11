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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	documentsparser "github.com/greenpau/go-authcrunch/pkg/authn/documents/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// Exercise serialized root configuration, custom cookies, browser refresh,
// administrative isolation and storage lifecycle through the public Server API.
// These consumer routes are independent of the private portal dispatcher.
var documentsEndpoints = map[string]struct {
	method, path string
	body         bool
}{
	"bootstrap":     {"GET", "/api/documents/bootstrap", false},
	"key.fetch":     {"GET", "/api/documents/keys/fetch", false},
	"key.register":  {"PUT", "/api/documents/keys/register", true},
	"file.allocate": {"POST", "/api/documents/files/allocate", true},
	"file.manifest": {"PUT", "/api/documents/file/{id}/manifest", true},
	"chunk.put":     {"PUT", "/api/documents/file/{id}/chunk/{idx}/put", true},
	"file.commit":   {"POST", "/api/documents/file/{id}/commit", false},
	"file.list":     {"GET", "/api/documents/files", false},
	"file.fetch":    {"GET", "/api/documents/file/{id}/fetch", false},
	"chunk.fetch":   {"GET", "/api/documents/file/{id}/chunk/{idx}/fetch", false},
	"key.lookup":    {"GET", "/api/documents/key/{user_id}/lookup", false},
	"share.put":     {"PUT", "/api/documents/file/{id}/share/{user_id}/put", true},
	"share.list":    {"GET", "/api/documents/file/{id}/share/list", false},
	"share.delete":  {"DELETE", "/api/documents/file/{id}/share/{user_id}/delete", false},
	"file.delete":   {"DELETE", "/api/documents/file/{id}/delete", false},
	"key.reset":     {"POST", "/api/documents/keys/reset", true},
}

func documentsRequest(t *testing.T, operation string, payload any) (string, string, string) {
	t.Helper()
	endpoint, ok := documentsEndpoints[operation]
	if !ok {
		t.Fatal("unknown Documents operation")
	}
	if payload == nil {
		payload = struct{}{}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	path := endpoint.path
	for _, name := range []string{"id", "user_id", "idx"} {
		placeholder := "{" + name + "}"
		if !strings.Contains(path, placeholder) {
			continue
		}
		value, ok := fields[name]
		if !ok {
			t.Fatal("missing resource parameter", name)
		}
		path = strings.ReplaceAll(path, placeholder, url.PathEscape(fmt.Sprint(value)))
		delete(fields, name)
	}
	if operation == "file.list" {
		if after, ok := fields["after"]; ok {
			path += "?after=" + url.QueryEscape(fmt.Sprint(after))
			delete(fields, "after")
		}
	}
	body := ""
	if endpoint.body || len(fields) > 0 {
		data, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		body = string(data)
	}
	return endpoint.method, path, body
}

func TestE2EServerDocumentsComposition(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := newServerCompositionFixture(t, true, func(c *authcrunch.Config) {
		portal := c.AuthenticationPortals[0]
		config, err := documentsparser.NewDocumentsAPIConfigFromDirectives([]string{
			cfgutil.EncodeArgs([]string{"enable", "documents", "api"}),
			cfgutil.EncodeArgs([]string{"documents", "api", "database", filepath.Join(dir, "documents.db")}),
			cfgutil.EncodeArgs([]string{"documents", "api", "public", "origin", portal.RefreshTokens.PublicOrigin}),
			"documents api base path /tenant/auth", "documents api realms local",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := portal.ConfigureDocumentsAPI(config); err != nil {
			t.Fatal(err)
		}
	})
	headers := http.Header{"Origin": {f.origin}, "Content-Type": {"application/json"}}
	request := func(operation string, payload any, want int) compositionResponse {
		t.Helper()
		method, path, body := documentsRequest(t, operation, payload)
		response := f.request(t, method, path, body, headers)
		if response.status != want {
			t.Fatalf("documents server %s: HTTP %d, want %d", operation, response.status, want)
		}
		if want == http.StatusOK {
			var body map[string]json.RawMessage
			if json.Unmarshal(response.body, &body) != nil || len(body) == 0 || body["operation"] != nil || body["result"] != nil {
				t.Fatal("invalid direct Documents response")
			}
		}
		return response
	}
	f.login(t, "local", "alice")
	bootstrap := compositionJSON(t, request("bootstrap", nil, http.StatusOK))
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := private.PublicKey().Bytes()
	sum := sha256.Sum256(public)
	binary := base64.RawURLEncoding.EncodeToString
	key := documents.Key{UserID: bootstrap["user_id"].(string), KeyID: binary(sum[:]), PublicKey: binary(public), Vault: &documents.Vault{Salt: binary(make([]byte, 32)), Nonce: binary(make([]byte, 12)), Ciphertext: binary(make([]byte, 48))}}
	request("key.register", map[string]any{"key": key}, http.StatusOK)
	allocation := request("file.allocate", map[string]any{"size": 16, "chunks": 1}, http.StatusOK)
	var file documents.File
	if json.Unmarshal(allocation.body, &file) != nil || !documents.ValidID(file.ID) {
		t.Fatal("documents root allocation")
	}
	manifest := documents.Manifest{Metadata: binary(make([]byte, 32)), Envelope: documents.Envelope{KeyID: key.KeyID, EphemeralKey: key.PublicKey, Ciphertext: binary(make([]byte, 48))}}
	request("file.manifest", map[string]any{"id": file.ID, "manifest": manifest}, http.StatusOK)
	request("chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": binary(make([]byte, 16))}, http.StatusOK)
	request("file.commit", map[string]any{"id": file.ID}, http.StatusOK)

	// Administrative authority confers no access to Alice's file or vault.
	f.login(t, "local", "admin")
	request("file.fetch", map[string]any{"id": file.ID}, http.StatusNotFound)
	other := compositionJSON(t, request("key.lookup", map[string]any{"user_id": key.UserID}, http.StatusOK))
	if other["vault"] != nil {
		t.Fatal("administrator obtained private vault representation")
	}
	f.login(t, "local", "alice")
	refreshHeaders := http.Header{"Origin": {f.origin}, "Content-Type": {"application/json"}, "X-Authcrunch-Refresh": {"1"}}
	session := f.request(t, "POST", "/api/refresh_session", "{}", refreshHeaders)
	compositionStatus(t, session, http.StatusOK)
	refreshHeaders.Set("X-Authcrunch-Refresh-Session", compositionJSON(t, session)["session_id"].(string))
	compositionStatus(t, f.request(t, "POST", "/api/refresh_token", "{}", refreshHeaders), http.StatusOK)
	request("chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, http.StatusOK)
	refreshHeaders.Del("X-Authcrunch-Refresh-Session")
	compositionStatus(t, f.request(t, "POST", "/api/logout", "{}", refreshHeaders), http.StatusOK)
	request("bootstrap", nil, http.StatusUnauthorized)

	f.replace(t, false, "")
	f.login(t, "local", "alice")
	restored := compositionJSON(t, request("bootstrap", nil, http.StatusOK))
	if restored["user_id"] != bootstrap["user_id"] || restored["portal_id"] != bootstrap["portal_id"] {
		t.Fatal("root restart changed Documents identity")
	}
	request("chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, http.StatusOK)
	request("file.delete", map[string]any{"id": file.ID}, http.StatusOK)
}
