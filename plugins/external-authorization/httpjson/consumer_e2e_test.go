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

package httpjson_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	transformerconfig "github.com/greenpau/go-authcrunch/pkg/authn/transformer/config"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	bindingparser "github.com/greenpau/go-authcrunch/pkg/authz/external/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson/parser"
)

// Portable consumer: copied into an external module, with only public imports.
func TestE2EHTTPJSONAuthorization(t *testing.T) {
	if (*authz.Gatekeeper)(nil).SetExternalAuthorizer(nil) == nil {
		t.Fatal("nil gatekeeper accepted attachment")
	}
	const secret = "synthetic-httpjson-signing-key-for-tests-only"
	const password = "SyntheticHTTPJSONPassword123!"
	const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	app := httptest.NewUnstartedServer(nil)
	defer app.Close()
	origin := "https://" + app.Listener.Addr().String()
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: password, Roles: []string{"viewer"}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAPIKey(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "synthetic fixture"}}); err != nil {
		t.Fatal(err)
	}
	var stores []ids.IdentityStore
	var transforms []*transformerconfig.Config
	for _, realm := range []string{"north", "south"} {
		store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: realm, Kind: "local", Params: map[string]any{"path": dbPath, "realm": realm}}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Configure(); err != nil {
			t.Fatal(err)
		}
		stores = append(stores, store)
		transform, err := transformerparser.NewUserTransformerConfigFromDirectives([]string{"match realm " + realm, "add tenant " + realm + " as string", "add foo bar as string", "add hidden never-send as string"})
		if err != nil {
			t.Fatal(err)
		}
		transforms = append(transforms, transform)
	}
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "httpjson", IdentityStores: []string{"north", "south"}, CookieConfig: cookie.NewConfig(), UserTransformerConfigs: transforms, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + secret}}, Logger: zap.NewNop(), IdentityStores: stores})
	if err != nil {
		t.Fatal(err)
	}
	defer portal.Close()
	var mode atomic.Value
	mode.Store("allow")
	var decisions, upstream atomic.Int64
	canceled, started := make(chan struct{}), make(chan struct{})
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decisions.Add(1)
		if r.Method != "POST" || r.URL.Path != "/decide" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected decision request transport")
		}
		var input external.Request
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&input) != nil {
			t.Error("invalid decision JSON")
			w.WriteHeader(400)
			return
		}
		if input.Identity.Subject != "alice" || input.Policy != "reports" || input.Version != "v1" || len(input.Attributes) != 1 || input.Attributes["foo"] != "bar" || strings.Contains(input.Resource, "?") {
			t.Error("incorrect decision input or excessive disclosure")
		}
		current := mode.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		switch current {
		case "outage":
			http.Error(w, "private-service-canary", 503)
			return
		case "malformed":
			_, _ = io.WriteString(w, `{"decision":true}`)
			return
		case "empty":
			_, _ = io.WriteString(w, `{}`)
			return
		case "compressed":
			w.Header().Set("Content-Encoding", "gzip")
			writer := gzip.NewWriter(w)
			_, _ = io.WriteString(writer, `{"decision":"allow","policy":"reports","version":"v1"}`+strings.Repeat(" ", 4096))
			_ = writer.Close()
			return
		case "timeout", "cancel":
			if current == "cancel" {
				close(started)
			}
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
				t.Error("request cancellation not delivered")
			}
			if current == "cancel" {
				close(canceled)
			}
			return
		}
		decision := "allow"
		if current == "deny" || input.Identity.Tenant != "north" || input.Action != "GET" || (input.Resource != "/private/read" && input.Resource != "/private/read ") {
			decision = "deny"
		}
		if current == "path-deny" && input.Resource == "/private/../private/write" {
			decision = "allow"
		}
		version := input.Version
		if current == "version" {
			version = "v2"
		}
		_ = json.NewEncoder(w).Encode(external.Result{Decision: decision, Policy: input.Policy, Version: version})
	}))
	defer service.Close()
	cfg, err := parser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"endpoint", service.URL + "/decide"}), "timeout 2s"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored httpjson.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	backend, err := httpjson.New(&restored, service.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	gates := make(map[string]*authz.Gatekeeper)
	for _, name := range []string{"jwt", "proxy", "off", "local-deny"} {
		conditions := []string{"match roles viewer"}
		if name == "local-deny" {
			conditions = []string{"match roles administrator"}
		}
		policy := &authz.PolicyConfig{Name: name, AuthRedirectDisabled: true, ValidateBearerHeader: true, ValidateMethodPath: true, PassClaimsWithHeaders: true, RawCryptoKeyStoreConfig: []string{"crypto key verify " + secret}, AccessListRules: []*acl.RuleConfiguration{{Conditions: conditions, Action: "allow stop"}}, BypassConfigs: []*bypass.Config{{MatchType: "exact", URI: "/public"}}}
		issuer := origin + "/auth/login"
		if name == "proxy" {
			issuer = "authp"
			policy.AuthProxyRawConfig = []string{"basic auth portal httpjson realm north", "api key auth portal httpjson realm north"}
		}
		gate, err := authz.NewGatekeeper(policy, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Close()
		if name == "proxy" {
			if err := gate.AddAuthenticators([]authproxy.Authenticator{portal}); err != nil {
				t.Fatal(err)
			}
		}
		if name != "off" {
			binding, err := bindingparser.NewExternalAuthorizationConfigFromDirectives([]string{"policy reports", "version v1", cfgutil.EncodeArgs([]string{"issuer", issuer}), "realm north", "tenant claim tenant", "attribute foo", "timeout 500ms"})
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			var restored external.Config
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			authorizer, err := external.New(&restored, backend)
			if err != nil {
				t.Fatal(err)
			}
			if err := gate.SetExternalAuthorizer(authorizer); err != nil {
				t.Fatal(err)
			}
			if gate.SetExternalAuthorizer(nil) == nil {
				t.Fatal("nil attachment disabled enforcement")
			}
		}
		gates[name] = gate
	}
	app.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth/") {
			_ = portal.ServeHTTP(r.Context(), w, r, requests.NewRequest())
			return
		}
		name := r.Header.Get("X-Fixture-Gate")
		if name == "" {
			name = "jwt"
		}
		gate := gates[name]
		if gate == nil {
			http.Error(w, "unknown gate", 400)
			return
		}
		ar := requests.NewAuthorizationRequest()
		_ = gate.Authenticate(w, r, ar)
		if !ar.Response.Authorized && !ar.Response.Bypassed {
			return
		}
		upstream.Add(1)
		w.Header().Set("X-Upstream-Roles", r.Header.Get("X-Token-User-Roles"))
		w.WriteHeader(204)
	})
	// Track whether the gatekeeper wrote a response before applying the host's
	// error fallback. The wrapping handler owns this behavior, as a real host does.
	app.Config.Handler = hostStatusHandler{next: app.Config.Handler}
	app.StartTLS()
	client := app.Client()
	client.Timeout = 5 * time.Second
	login := func(realm string) string {
		t.Helper()
		c, err := authclient.NewClient(&authclient.Config{BaseURL: origin + "/auth", Realm: realm, Username: "alice", Password: password}, authclient.Options{HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		result, err := c.Authenticate(t.Context())
		if err != nil || result == nil || result.AccessToken == "" {
			t.Fatal("TLS password login failed")
		}
		return result.AccessToken
	}
	token := login("north")
	other := login("south")
	send := func(kind, gate, method, path, credential string, want int, called bool) {
		t.Helper()
		beforeCalls, beforeUpstream := decisions.Load(), upstream.Load()
		req, err := http.NewRequestWithContext(t.Context(), method, origin+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Fixture-Gate", gate)
		req.Header.Set("X-Token-User-Roles", "administrator")
		req.Header.Set("X-Subject", "mallory")
		switch kind {
		case "basic":
			req.SetBasicAuth("alice", password)
			req.Header.Set("X-Auth-Realm", "north")
		case "api":
			req.Header.Set("X-API-Key", apiKey)
			req.Header.Set("X-Auth-Realm", "north")
		default:
			if credential != "" {
				req.Header.Set("Authorization", "Bearer "+credential)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s %s: HTTP %d, want %d", kind, gate, path, resp.StatusCode, want)
		}
		if called != (decisions.Load() > beforeCalls) {
			t.Fatal("required decision skipped or local rejection disclosed identity")
		}
		if want == 204 {
			if upstream.Load() != beforeUpstream+1 {
				t.Fatal("authorized request not forwarded")
			}
			if strings.Contains(resp.Header.Get("X-Upstream-Roles"), "administrator") {
				t.Fatal("untrusted roles reached upstream")
			}
		} else if upstream.Load() != beforeUpstream {
			t.Fatal("denied request reached upstream")
		}
		if strings.Contains(string(body), "private-service-canary") {
			t.Fatal("backend response disclosed")
		}
	}
	for range 2 {
		send("bearer", "jwt", "GET", "/private/read?secret=hidden", token, 204, true)
	}
	send("bearer", "jwt", "GET", "/private/read%20", token, 204, true)
	// Rejected replacement configuration leaves the active backend usable.
	if candidate, err := parser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{"endpoint " + service.URL + "#"}); candidate != nil || err == nil {
		t.Fatal("invalid replacement endpoint accepted")
	}
	if candidate, err := httpjson.New(&httpjson.Config{Endpoint: service.URL + ":0"}, service.Client()); candidate != nil || err == nil {
		t.Fatal("invalid typed replacement endpoint accepted")
	}
	send("bearer", "jwt", "GET", "/private/read", token, 204, true)
	mode.Store("deny")
	send("bearer", "jwt", "GET", "/private/read", token, 403, true)
	mode.Store("allow")
	send("bearer", "jwt", "GET", "/private/read", token, 204, true)
	send("bearer", "local-deny", "GET", "/private/read", token, 403, false)
	send("bearer", "jwt", "GET", "/private/read", other, 403, false)
	send("bearer", "jwt", "GET", "/private/read", "invalid-token", 401, false)
	send("bearer", "jwt", "GET", "/public", "", 204, false)
	send("bearer", "jwt", "POST", "/private/read", token, 403, true)
	send("bearer", "jwt", "GET", "/private/write", token, 403, true)
	send("bearer", "jwt", "GET", "/private%2Fread", token, 403, false)
	mode.Store("path-deny")
	beforePaths := decisions.Load()
	send("bearer", "jwt", "GET", "/private/../private/write", token, 403, true)
	if decisions.Load() != beforePaths+2 {
		t.Fatal("cleaned path was not evaluated after original path allowed")
	}
	for _, failure := range []string{"outage", "malformed", "empty", "version", "timeout", "compressed"} {
		mode.Store(failure)
		send("bearer", "jwt", "GET", "/private/read", token, 403, true)
	}
	mode.Store("deny")
	send("bearer", "off", "GET", "/private/read", token, 204, false)
	for _, kind := range []string{"basic", "api"} {
		mode.Store("allow")
		for range 2 {
			send(kind, "proxy", "GET", "/private/read", "", 204, true)
		}
		mode.Store("deny")
		send(kind, "proxy", "GET", "/private/read", "", 403, true)
	}
	mode.Store("cancel")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", origin+"/private/read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	done := make(chan error, 1)
	before := upstream.Load()
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("decision request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("unexpected cancellation result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not cancel")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not reach HTTP service")
	}
	if upstream.Load() != before {
		t.Fatal("canceled request forwarded")
	}
	mode.Store("allow")
	send("bearer", "jwt", "GET", "/private/read", token, 204, true)
	backend.Close()
	send("bearer", "jwt", "GET", "/private/read", token, 403, false)
}

type hostStatusWriter struct {
	http.ResponseWriter
	written bool
}

func (w *hostStatusWriter) WriteHeader(status int) {
	w.written = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *hostStatusWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

type hostStatusHandler struct{ next http.Handler }

func (h hostStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	recorder := &hostStatusWriter{ResponseWriter: w}
	h.next.ServeHTTP(recorder, r)
	if !recorder.written {
		http.Error(w, "unauthorized", 401)
	}
}
