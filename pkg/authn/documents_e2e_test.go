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

package authn_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	documentsparser "github.com/greenpau/go-authcrunch/pkg/authn/documents/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

type documentsE2E struct {
	server         *httptest.Server
	client         *http.Client
	base, database string
	mu             sync.RWMutex
	portal         *authn.Portal
	store          *local.IdentityStore
	newPortal      func() *authn.Portal
}

func TestE2EDocumentsRejectsReplacedSessionToken(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	client := *f.client
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	browser := &oidcE2EFixture{server: f.server, client: &client, issuer: f.server.URL + f.base}
	webAuthnEnrollmentLogin(t, browser, "alice", tests.TestPwd1)
	previous := loginIdentityCookie(browser, "AUTHP_ACCESS_TOKEN")
	f.message(t, previous, "bootstrap", nil, http.StatusOK)
	key := f.enroll(t, previous)
	file := documentsDecode[documents.File](t, f.message(t, previous, "file.allocate", map[string]any{"size": 32, "chunks": 1}, http.StatusOK))
	f.message(t, previous, "file.manifest", map[string]any{"id": file.ID, "manifest": documents.Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: documentsEnvelope(key)}}, http.StatusOK)
	// Switch accounts after initial admission, while the server waits for the
	// body. The second session check must reject without persisting a chunk.
	documentsDelayedRequest(t, f, previous, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, func() {
		oidcE2EStatus(t, browser.request(t, http.MethodGet, "/login?fresh=1", nil, nil), http.StatusOK)
		webAuthnEnrollmentLogin(t, browser, "bob", tests.TestPwd2)
	}, http.StatusUnauthorized)
	f.message(t, previous, "bootstrap", nil, http.StatusUnauthorized)
	f.message(t, loginIdentityCookie(browser, "AUTHP_ACCESS_TOKEN"), "bootstrap", nil, http.StatusOK)
	fresh := f.login(t, "alice")
	ciphertext := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	f.message(t, fresh, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": ciphertext}, http.StatusOK)
	f.message(t, fresh, "file.commit", map[string]any{"id": file.ID}, http.StatusOK)
	chunk := documentsDecode[map[string]string](t, f.message(t, fresh, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, http.StatusOK))
	if chunk["ciphertext"] != ciphertext {
		t.Fatal("replaced session wrote a chunk while the body was in flight")
	}
}

func newDocumentsE2E(t *testing.T, base string, enabled bool, customize ...func(*authn.PortalConfig)) *documentsE2E {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := identity.NewDatabase(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob", "charlie"} {
		password := tests.TestPwd1Hash(t)
		if name == "bob" {
			password = tests.TestPwd2Hash(t)
		}
		if err := db.AddUser(&requests.Request{User: requests.User{Username: name, Email: name + "@example.test", Password: password, Roles: []string{"authp/user"}}}); err != nil {
			t.Fatal("provision documents identity")
		}
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{"path": filepath.Join(dir, "users.json"), "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	f := &documentsE2E{base: base, store: store.(*local.IdentityStore), database: filepath.Join(dir, "documents.db")}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_documents_test/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<!doctype html><title>Documents browser fixture</title>")
			return
		case "/_documents_test/crypto.mjs":
			w.Header().Set("Content-Type", "text/javascript")
			http.ServeFile(w, r, "documents/client/crypto.mjs")
			return
		}
		f.mu.RLock()
		defer f.mu.RUnlock()
		if err := f.portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("documents portal response failed")
		}
	}))
	t.Cleanup(f.server.Close)
	origin := "https://" + f.server.Listener.Addr().String()
	f.newPortal = func() *authn.Portal {
		statements := [][]string{{"database", f.database}, {"public", "origin", origin}, {"base", "path", base}, {"realms", "local"}, {"max", "file", "bytes", "4194304"}, {"max", "user", "bytes", "8388608"}, {"max", "total", "bytes", "16777216"}, {"max", "user", "files", "4"}, {"max", "recipients", "2"}}
		encoded := []string{}
		if enabled {
			encoded = append(encoded, cfgutil.EncodeArgs([]string{"enable", "documents", "api"}))
		}
		for _, line := range statements {
			encoded = append(encoded, cfgutil.EncodeArgs(append([]string{"documents", "api"}, line...)))
		}
		config, err := documentsparser.NewDocumentsAPIConfigFromDirectives(encoded)
		if err != nil {
			t.Fatal(err)
		}
		portalConfig := &authn.PortalConfig{Name: "documents-e2e", IdentityStores: []string{f.store.GetName()}, RawCryptoKeyStoreConfig: []string{e2eRSAKey}, UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"exact match sub alice"}, Actions: []string{"overwrite sub bob", "overwrite email bob@example.test"}}}}
		if err := portalConfig.ConfigureDocumentsAPI(config); err != nil {
			t.Fatal(err)
		}
		for _, change := range customize {
			change(portalConfig)
		}
		portal, err := authn.NewPortal(authn.PortalParameters{Config: portalConfig, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{f.store}})
		if err != nil {
			t.Fatal(err)
		}
		return portal
	}
	f.portal = f.newPortal()
	f.server.StartTLS()
	f.client = f.server.Client()
	f.client.Timeout = 15 * time.Second
	t.Cleanup(func() { f.server.Close(); f.portal.Close() })
	return f
}
func (f *documentsE2E) login(t *testing.T, name string) string {
	t.Helper()
	password := tests.TestPwd1
	if name == "bob" {
		password = tests.TestPwd2
	}
	client := *f.client
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fixture := &oidcE2EFixture{server: f.server, client: &client, issuer: f.server.URL + strings.TrimSuffix(f.base, "/")}
	webAuthnEnrollmentLogin(t, fixture, name, password)
	token := loginIdentityCookie(fixture, "AUTHP_ACCESS_TOKEN")
	if token == "" {
		t.Fatal("documents browser login failed")
	}
	return token
}

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

func (f *documentsE2E) message(t *testing.T, token, operation string, payload any, want int, headers ...http.Header) []byte {
	t.Helper()
	method, path, body := documentsRequest(t, operation, payload)
	raw := f.raw(t, token, method, strings.TrimPrefix(path, "/api/documents"), body, want, headers...)
	if want != http.StatusOK {
		return raw
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(raw, &response) != nil || len(response) == 0 || response["operation"] != nil || response["result"] != nil {
		t.Fatal("invalid direct Documents response", operation)
	}
	if operation == "key.register" || operation == "key.reset" || operation == "file.manifest" || operation == "chunk.put" || operation == "file.commit" || operation == "share.put" || operation == "share.delete" || operation == "file.delete" {
		if len(response) != 1 || string(response["success"]) != "true" {
			t.Fatal("missing mutation confirmation", operation)
		}
	}
	return raw
}
func (f *documentsE2E) raw(t *testing.T, token, method, suffix, body string, want int, headers ...http.Header) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+strings.TrimSuffix(f.base, "/")+"/api/documents"+suffix, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, h := range headers {
		maps.Copy(req.Header, h)
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal("documents request failed", method, suffix)
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal("documents response read failed")
	}
	if response.StatusCode != want {
		t.Fatalf("documents %s %s: HTTP %d, want %d", method, suffix, response.StatusCode, want)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("documents response lacks privacy headers")
	}
	if want == 405 {
		matched := false
		for _, endpoint := range documentsEndpoints {
			pattern := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(endpoint.path, `[^/]+`)
			if regexp.MustCompile("^" + strings.TrimPrefix(pattern, "/api/documents") + "$").MatchString(suffix) {
				matched = true
				if response.Header.Get("Allow") != endpoint.method {
					t.Fatal("Documents advertised an incorrect method")
				}
			}
		}
		if !matched {
			t.Fatal("method check did not match a documented resource")
		}
	}
	if method != http.MethodHead {
		openAPIJourneyResponse(t, f.server.URL+strings.TrimSuffix(f.base, "/"), req.URL, method, response.StatusCode, response.Header, result)
	}
	return result
}
func documentsDecode[T any](t *testing.T, data []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal("invalid documents JSON response")
	}
	return value
}
func (f *documentsE2E) enroll(t *testing.T, token string) documents.Key {
	t.Helper()
	bootstrap := documentsDecode[map[string]any](t, f.message(t, token, "bootstrap", nil, 200))
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := private.PublicKey().Bytes()
	sum := sha256.Sum256(public)
	encode := base64.RawURLEncoding.EncodeToString
	key := documents.Key{UserID: bootstrap["user_id"].(string), KeyID: encode(sum[:]), PublicKey: encode(public), Vault: &documents.Vault{Salt: encode(make([]byte, 32)), Nonce: encode(make([]byte, 12)), Ciphertext: encode(make([]byte, 48))}}
	f.message(t, token, "key.register", map[string]any{"key": key}, 200)
	return key
}
func documentsEnvelope(key documents.Key) documents.Envelope {
	return documents.Envelope{KeyID: key.KeyID, EphemeralKey: key.PublicKey, Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 48))}
}
func (f *documentsE2E) ready(t *testing.T, token string, key documents.Key) documents.File {
	t.Helper()
	file := documentsDecode[documents.File](t, f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 200))
	f.message(t, token, "file.manifest", map[string]any{"id": file.ID, "manifest": documents.Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: documentsEnvelope(key)}}, 200)
	f.message(t, token, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, 200)
	f.message(t, token, "file.commit", map[string]any{"id": file.ID}, 200)
	return file
}
func TestE2EDocumentsAuthorizationPersistenceAndIdentity(t *testing.T) {
	f := newDocumentsE2E(t, "/tenant/xauth", true)
	aliceToken, bobToken := f.login(t, "alice"), f.login(t, "bob")
	alice, bob := f.enroll(t, aliceToken), f.enroll(t, bobToken)
	if alice.UserID == bob.UserID {
		t.Fatal("transformed claim stole another identity")
	}
	for name, key := range map[string]documents.Key{"alice": alice, "bob": bob} {
		lookup := &requests.Request{User: requests.User{Username: name}}
		if err := f.store.Request(operator.IdentifyUser, lookup); err != nil {
			t.Fatal(err)
		}
		if key.UserID != lookup.Authentication.UserID {
			t.Fatal("Documents ownership does not equal local database id")
		}
	}
	file := f.ready(t, aliceToken, alice)
	f.message(t, bobToken, "file.fetch", map[string]any{"id": file.ID}, 404)
	f.message(t, aliceToken, "share.put", map[string]any{"id": file.ID, "user_id": bob.UserID, "envelope": documentsEnvelope(bob)}, 200)
	shared := documentsDecode[documents.File](t, f.message(t, bobToken, "file.fetch", map[string]any{"id": file.ID}, 200))
	if shared.Owner != alice.UserID || shared.Envelope.KeyID != bob.KeyID {
		t.Fatal("sharing changed ownership or returned wrong envelope")
	}
	page := documentsDecode[documents.Page](t, f.message(t, bobToken, "file.list", nil, 200))
	if len(page.Files) != 1 || page.Files[0].ID != file.ID || page.Files[0].Metadata != "" || page.Files[0].Envelope != nil {
		t.Fatal("shared listing returned wrong descriptors")
	}
	after := documentsDecode[documents.Page](t, f.message(t, bobToken, "file.list", map[string]any{"after": file.ID}, 200))
	if len(after.Files) != 0 {
		t.Fatal("message cursor repeated the last file")
	}
	grants := documentsDecode[struct {
		Recipients []string `json:"recipients"`
	}](t, f.message(t, aliceToken, "share.list", map[string]any{"id": file.ID}, 200))
	if len(grants.Recipients) != 1 || grants.Recipients[0] != bob.UserID {
		t.Fatal("owner recipient listing")
	}
	f.message(t, bobToken, "file.delete", map[string]any{"id": file.ID}, 404)
	f.message(t, bobToken, "share.list", map[string]any{"id": file.ID}, 404)
	public := documentsDecode[documents.Key](t, f.message(t, aliceToken, "key.lookup", map[string]any{"user_id": bob.UserID}, 200))
	if public.Vault != nil {
		t.Fatal("vault exposed to another user")
	}
	selfPublic := documentsDecode[documents.Key](t, f.message(t, aliceToken, "key.lookup", map[string]any{"user_id": alice.UserID}, 200))
	if selfPublic.Vault != nil || selfPublic.KeyID != alice.KeyID {
		t.Fatal("public lookup returned a private representation")
	}
	f.mu.Lock()
	f.portal.Close()
	f.portal = f.newPortal()
	f.mu.Unlock()
	f.message(t, aliceToken, "file.fetch", map[string]any{"id": file.ID}, 401)
	aliceToken, bobToken = f.login(t, "alice"), f.login(t, "bob")
	if value := documentsDecode[documents.Key](t, f.message(t, aliceToken, "key.fetch", nil, 200)); value.KeyID != alice.KeyID {
		t.Fatal("restart lost key")
	}
	f.message(t, bobToken, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 200)
	f.message(t, aliceToken, "share.delete", map[string]any{"id": file.ID, "user_id": bob.UserID}, 200)
	f.message(t, bobToken, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 404)
	lookup := &requests.Request{User: requests.User{Username: "alice"}}
	if err := f.store.Request(operator.IdentifyUser, lookup); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeUserSessions(t.Context(), lookup.Authentication.UserID); err != nil {
		t.Fatal(err)
	}
	f.message(t, aliceToken, "file.fetch", map[string]any{"id": file.ID}, 401)
	aliceToken = f.login(t, "alice")
	f.message(t, aliceToken, "file.fetch", map[string]any{"id": file.ID}, 200)
	if err := f.store.DeleteUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	f.message(t, aliceToken, "file.fetch", map[string]any{"id": file.ID}, 401)
	if err := f.store.Request(operator.AddUser, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal(err)
	}
	recreated := f.login(t, "alice")
	f.message(t, recreated, "file.fetch", map[string]any{"id": file.ID}, 404)
	f.message(t, recreated, "key.fetch", nil, 404)
}
func TestE2EDocumentsPublicPointEncoding(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	aliceToken, bobToken := f.login(t, "alice"), f.login(t, "bob")
	alice, bob := f.enroll(t, aliceToken), f.enroll(t, bobToken)
	file := f.ready(t, aliceToken, alice)
	manifest := documents.Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: documentsEnvelope(alice)}
	for _, prefix := range []byte{5, 6, 7, 4} {
		point, err := base64.RawURLEncoding.DecodeString(alice.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		point[0] = prefix
		if prefix == 4 {
			clear(point[1:]) // Correct encoding prefix, but not a curve point.
		}
		key := alice
		key.PublicKey = base64.RawURLEncoding.EncodeToString(point)
		sum := sha256.Sum256(point)
		key.KeyID = base64.RawURLEncoding.EncodeToString(sum[:])
		// Recompute the fingerprint so rejection proves point validation.
		f.message(t, aliceToken, "key.register", map[string]any{"key": key}, 400)
		badManifest := manifest
		badManifest.Envelope.EphemeralKey = key.PublicKey
		f.message(t, aliceToken, "file.manifest", map[string]any{"id": file.ID, "manifest": badManifest}, 400)
		envelope := documentsEnvelope(bob)
		envelope.EphemeralKey = key.PublicKey
		f.message(t, aliceToken, "share.put", map[string]any{"id": file.ID, "user_id": bob.UserID, "envelope": envelope}, 400)
	}
	f.message(t, aliceToken, "key.register", map[string]any{"key": alice}, 200)
	f.message(t, aliceToken, "file.manifest", map[string]any{"id": file.ID, "manifest": manifest}, 200)
	f.message(t, aliceToken, "share.put", map[string]any{"id": file.ID, "user_id": bob.UserID, "envelope": documentsEnvelope(bob)}, 200)
	f.message(t, bobToken, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 200)
}

func TestE2EDocumentsRequestBoundariesAndReset(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	registration, err := json.Marshal(map[string]any{"key": key})
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{`"ſalt"`, `"\u017falt"`} {
		f.raw(t, token, "PUT", "/keys/register", strings.Replace(string(registration), `"salt"`, alias, 1), 400)
	}
	f.message(t, "", "bootstrap", nil, 401)
	f.message(t, token, "bootstrap", nil, 403, http.Header{"Origin": {"https://untrusted.example.test"}})
	f.message(t, token, "key.fetch", nil, 403, http.Header{"Origin": {f.server.URL, f.server.URL}})
	f.message(t, token, "key.fetch", nil, 403, http.Header{"Sec-Fetch-Site": {"same-site"}})
	f.message(t, token, "key.register", map[string]any{"key": key}, 415, http.Header{"Content-Type": {"text/plain"}})
	f.raw(t, token, "POST", "/files/allocate", strings.Repeat(" ", 1500000), 413)
	for _, tc := range []struct{ path, body string }{
		{"bootstrap", `null`}, {"bootstrap", `[]`},
		{"keys/reset", `{}`}, {"bootstrap", `{} {}`},
		{"bootstrap", `{"operation":"bootstrap","payload":{}}`},
		{"bootstrap", `{"payload":{}}`}, {"bootstrap", `{"operation":"key.reset"}`},
		{"files/allocate", `{"size":32,"chunks":1,"filename":"plaintext"}`},
		{"files/allocate", `{"size":32.5,"chunks":1}`}, {"files/allocate", `{"size":32}`},
		{"files", `{"after":"bad"}`}, {"bootstrap", `{"id":"ignored"}`},
		{"files/allocate", `{"Size":32,"chunks":1}`},
		{"files/allocate", `{"size":null,"chunks":1}`},
		{"files/allocate", `{"size":32,"size":16,"chunks":1}`},
		{"files/allocate", `{"size":32,"\u0073ize":16,"chunks":1}`},
	} {
		method := "POST"
		if tc.path == "bootstrap" || tc.path == "files" {
			method = "GET"
		}
		f.raw(t, token, method, "/"+tc.path, tc.body, 400)
	}
	f.raw(t, token, "POST", "/files/allocate", `{}`+strings.Repeat(" ", 65537), 413)
	for _, endpoint := range documentsEndpoints {
		path := strings.NewReplacer("{id}", strings.Repeat("A", 43), "{user_id}", key.UserID, "{idx}", "0").Replace(endpoint.path)
		path = strings.TrimPrefix(path, "/api/documents")
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"} {
			if method != endpoint.method {
				f.raw(t, token, method, path, "", 405)
			}
		}
		for _, query := range []string{"?", "?operation=bootstrap", "?after=bad"} {
			f.raw(t, token, endpoint.method, path+query, "", 400)
		}
		if !endpoint.body {
			f.raw(t, token, endpoint.method, path, `{}`, 400)
		}
	}
	for _, query := range []string{"?after=", "?After=" + strings.Repeat("A", 43), "?after=" + strings.Repeat("A", 43) + "&after=" + strings.Repeat("A", 43), "?%61fter=" + strings.Repeat("A", 43)} {
		f.raw(t, token, "GET", "/files"+query, "", 400)
	}
	for _, path := range []string{"/file/bad/delete", "/file/" + strings.Repeat("A", 43) + "/chunk/01/fetch", "/key/bad/lookup"} {
		f.raw(t, token, "GET", path, "", 400)
	}
	for _, suffix := range []string{"", "/", "/key", "/keys", "/files/list", "/unknown/api/logout", "/unknown/api/profile", "/files/../key", "/keys/logout", "/bootstrap/", "/files/bad/chunks/0", "/%62ootstrap", "/keys%2ffetch", "/keys/get", "/file/get", "/chunk/get", "/key.fetch", "/keys//get", "/keys/fetch/", "/keys/fetch/extra"} {
		f.raw(t, token, "POST", suffix, `{}`, 404)
	}
	// Superseded collection paths must not remain as aliases, even with the
	// original method, valid fields and an authenticated session.
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/file/list", ""},
		{"POST", "/file/allocate", `{"size":32,"chunks":1}`},
		{"GET", "/key/fetch", ""},
		{"PUT", "/key/register", string(registration)},
		{"POST", "/key/reset", `{"user_id":"` + key.UserID + `","key_id":"` + key.KeyID + `"}`},
	} {
		f.raw(t, token, tc.method, tc.path, tc.body, 404)
	}
	f.raw(t, token, "GET", "/bootstrap", "", 415, http.Header{"Content-Encoding": {"identity"}})
	f.raw(t, token, "POST", "/files/allocate", `{}`, 415, http.Header{"Content-Type": {"application/json", "application/json"}})
	reset, err := json.Marshal(map[string]any{"user_id": key.UserID, "key_id": key.KeyID})
	if err != nil {
		t.Fatal(err)
	}
	f.raw(t, token, "GET", "/keys/fetch", string(reset), 400)
	f.raw(t, token, "GET", "/keys/fetch", `{"operation":"key.get","payload":{}}`, 400)
	f.message(t, token, "key.fetch", nil, 200)
	pending := documentsDecode[documents.File](t, f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 200))
	// Nonzero unused base64 bits must not alias otherwise well-sized bytes.
	f.message(t, token, "chunk.put", map[string]any{"id": pending.ID, "idx": 0, "ciphertext": strings.Repeat("A", 42) + "B"}, 400)
	for _, metadata := range []string{strings.Repeat("A", 21) + "B", strings.Repeat("A", 22) + "B", strings.Repeat("A", 25)} {
		f.message(t, token, "file.manifest", map[string]any{"id": pending.ID, "manifest": documents.Manifest{Metadata: metadata, Envelope: documentsEnvelope(key)}}, 400)
	}
	f.message(t, token, "file.commit", map[string]any{"id": pending.ID}, 409)
	f.message(t, token, "chunk.put", map[string]any{"id": pending.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, documents.ChunkSize+17))}, 413)
	f.message(t, token, "chunk.put", map[string]any{"id": pending.ID, "idx": -1, "ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, 400)
	file := f.ready(t, token, key)
	f.raw(t, token, "PUT", "/file/"+file.ID+"/chunk/0/put", `{"id":"`+pending.ID+`","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`, 400)
	f.raw(t, token, "DELETE", "/file/"+file.ID+"/delete", `{"id":"`+pending.ID+`"}`, 400)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
	f.message(t, token, "file.list", map[string]any{"after": file.ID}, 200)
	f.message(t, token, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, 409)
	for range 2 {
		f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 200)
	}
	f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 507)
	f.message(t, token, "key.reset", map[string]any{"user_id": key.UserID, "key_id": key.KeyID}, 200)
	f.message(t, token, "key.fetch", nil, 404)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 404)
	f.enroll(t, token)
	fresh := documentsDecode[documents.File](t, f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 200))
	f.message(t, token, "file.delete", map[string]any{"id": fresh.ID}, 200)
	page := documentsDecode[documents.Page](t, f.message(t, token, "file.list", nil, 200))
	if len(page.Files) != 0 {
		t.Fatal("reset or delete retained files")
	}
}

func TestE2EDocumentsRejectsAccessOnlyJSONLogin(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	client, err := authclient.NewClient(&authclient.Config{BaseURL: f.server.URL + f.base, Realm: "local", Username: "alice", Password: tests.TestPwd1}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil || credentials == nil || credentials.AccessToken == "" {
		t.Fatal("documents access-only login failed")
	}
	f.message(t, credentials.AccessToken, "bootstrap", nil, 401)
	// The same account becomes eligible through a fresh browser login.
	token := f.login(t, "alice")
	f.message(t, token, "bootstrap", nil, 200)
}

func TestE2EDocumentsConfigurationRejectsOriginAliases(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	for _, origin := range []string{f.server.URL + "#", "https://portal.example.test:", "https://portal.example.test:0443", "https://portal.example.test:65536", "https://bücher.example", "https://127.1"} {
		t.Run(origin, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			database := filepath.Join(dir, "documents.db")
			var input []string
			for _, args := range [][]string{{"enable", "documents", "api"}, {"documents", "api", "database", database}, {"documents", "api", "public", "origin", origin}, {"documents", "api", "realms", "local"}} {
				input = append(input, cfgutil.EncodeArgs(args))
			}
			if settings, err := documentsparser.NewDocumentsAPIConfigFromDirectives(input); err == nil || settings != nil {
				t.Fatal("public parser accepted a browser origin alias")
			}
			// Direct serialized config must enforce the same boundary before
			// provisioning or permanently binding a new database.
			config := &authn.PortalConfig{Name: "documents-invalid-origin", IdentityStores: []string{f.store.GetName()}, RawCryptoKeyStoreConfig: []string{e2eRSAKey}, API: &authn.APIConfig{DocumentsEnabled: true}, Documents: &documents.Config{Database: database, PublicOrigin: origin, Realms: []string{"local"}}}
			portal, err := authn.NewPortal(authn.PortalParameters{Config: config, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{f.store}})
			if portal != nil {
				portal.Close()
			}
			if err == nil || portal != nil {
				t.Fatal("portal accepted a browser origin alias")
			}
			if _, err := os.Stat(database); !os.IsNotExist(err) {
				t.Fatal("rejected configuration provisioned a Documents database")
			}
		})
	}
	// A quoted multiword keyword must not become a valid directive merely
	// because the parser joins its argument tokens. The surrounding settings
	// are otherwise sufficient to provision a working portal.
	var input []string
	for _, args := range [][]string{{"enable", "documents", "api"}, {"documents", "api", "database", f.database}, {"documents", "api", "public", "origin", f.server.URL}, {"documents", "api", "base", "path", f.base}, {"documents", "api", "realms", "local"}, {"documents", "api", "max file bytes", "1024"}} {
		input = append(input, cfgutil.EncodeArgs(args))
	}
	if settings, err := documentsparser.NewDocumentsAPIConfigFromDirectives(input); err == nil || settings != nil {
		t.Fatal("consumer parser accepted a combined keyword token")
	}
	// A failed replacement must not disturb an already running portal/store.
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
	f.message(t, token, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 200)
}

func TestE2EDocumentsRootMount(t *testing.T) {
	f := newDocumentsE2E(t, "/", true)
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	f.message(t, token, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 200)
	f.message(t, token, "file.delete", map[string]any{"id": file.ID}, 200)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 404)
}
func TestE2EDocumentsDisabledNamespace(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*authn.PortalConfig)
	}{
		{"omitted", func(c *authn.PortalConfig) { c.API, c.Documents = nil, nil }},
		{"storage alone", func(c *authn.PortalConfig) { c.API = nil }},
		{"admin and profile enabled", func(c *authn.PortalConfig) { c.API = &authn.APIConfig{AdminEnabled: true, ProfileEnabled: true} }},
		{"explicit disable", func(c *authn.PortalConfig) {
			settings, err := documentsparser.NewDocumentsAPIConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"disable", "documents", "api"})})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.ConfigureDocumentsAPI(settings); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid unused storage", func(c *authn.PortalConfig) { c.Documents.Database = "relative/unavailable" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDocumentsE2E(t, "/", false, tc.configure)
			for _, path := range []string{"", "/bootstrap", "/unknown/api/logout", "/files"} {
				f.raw(t, "", "POST", path, `{}`, 404)
			}
			if _, err := os.Stat(f.database); !os.IsNotExist(err) {
				t.Fatal("disabled documents provisioned storage")
			}
		})
	}
}

func TestE2EDocumentsRejectsCollidingIdentityStore(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	token := f.login(t, "alice")
	key := f.enroll(t, token)
	file := f.ready(t, token, key)
	// A distinct authoritative database containing a copied UUID must not inherit
	// ownership merely because its login and ID happen to match.
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(f.database), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(filepath.Dir(f.database), "other-users.json")
	if err := os.WriteFile(copied, raw, 0600); err != nil {
		t.Fatal(err)
	}
	other, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "other", Kind: "local", Params: map[string]any{"path": copied, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Configure(); err != nil {
		t.Fatal(err)
	}
	original := f.store
	f.mu.Lock()
	f.portal.Close()
	f.store = other.(*local.IdentityStore)
	f.portal = f.newPortal()
	f.mu.Unlock()
	token = f.login(t, "alice")
	for _, operation := range []string{"bootstrap", "key.fetch"} {
		f.message(t, token, operation, nil, 403)
	}
	f.message(t, token, "key.reset", map[string]any{"user_id": key.UserID, "key_id": key.KeyID}, 403)
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 403)
	f.mu.Lock()
	f.portal.Close()
	f.store = original
	f.portal = f.newPortal()
	f.mu.Unlock()
	token = f.login(t, "alice")
	f.message(t, token, "file.fetch", map[string]any{"id": file.ID}, 200)
}

func TestE2EDocumentsResetConfirmationBinding(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	aliceToken, bobToken := f.login(t, "alice"), f.login(t, "bob")
	alice, bob := f.enroll(t, aliceToken), f.enroll(t, bobToken)
	bobFile := f.ready(t, bobToken, bob)
	confirmation := map[string]any{"user_id": alice.UserID, "key_id": alice.KeyID}
	// Another tab has switched the browser's cookie after Alice's confirmation.
	f.message(t, "", "key.reset", confirmation, 409, http.Header{"Cookie": {"AUTHP_ACCESS_TOKEN=" + bobToken}})
	f.message(t, bobToken, "file.fetch", map[string]any{"id": bobFile.ID}, 200)
	f.message(t, aliceToken, "key.fetch", nil, 200)
	f.message(t, aliceToken, "key.reset", confirmation, 200)
	f.message(t, aliceToken, "key.reset", confirmation, 200) // Exact retry before reenrollment.
	replacement := f.enroll(t, aliceToken)
	fresh := f.ready(t, aliceToken, replacement)
	f.message(t, aliceToken, "key.reset", confirmation, 409) // Stale retry cannot erase the new vault.
	f.message(t, aliceToken, "file.fetch", map[string]any{"id": fresh.ID}, 200)
	own := documentsDecode[documents.Key](t, f.message(t, aliceToken, "key.fetch", nil, 200))
	if own.KeyID != replacement.KeyID {
		t.Fatal("stale reset deleted replacement registration")
	}
}
