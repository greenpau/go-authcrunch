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

package static_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	aclparser "github.com/greenpau/go-authcrunch/pkg/acl/parser"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	transformerconfig "github.com/greenpau/go-authcrunch/pkg/authn/transformer/config"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	enrichmentparser "github.com/greenpau/go-authcrunch/pkg/authz/enrichment/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static"
	staticparser "github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static/parser"
)

// Faults stay in tests; the static plugin only supplies configured claims.
type responseBackend struct {
	next     enrichment.Backend
	mode     string
	started  chan struct{}
	canceled chan struct{}
}

func (b *responseBackend) Lookup(ctx context.Context, req enrichment.Request) (*enrichment.Result, error) {
	if b.mode == "outage" || b.mode == "allow-stop" {
		return nil, fmt.Errorf("test backend unavailable")
	}
	if b.mode == "timeout" || b.mode == "cancel" {
		if b.started != nil {
			close(b.started)
		}
		<-ctx.Done()
		if b.canceled != nil {
			close(b.canceled)
		}
		return nil, ctx.Err()
	}
	result, err := b.next.Lookup(ctx, req)
	if err != nil {
		return nil, err
	}
	switch b.mode {
	case "missing":
		result.Attributes = nil
	case "wrong-type":
		result.Attributes["featureFlags"] = false
	case "literal":
		result.Attributes["foo"] = "${${bar}}"
	case "expired":
		result.ObservedAt = time.Now().Add(-time.Minute)
		result.ExpiresAt = time.Now().Add(-time.Second)
	case "reserved":
		result.Attributes = map[string]any{"roles": []string{"admin"}}
	case "too-deep":
		result.Attributes["depthLimitNulls"] = []any{result.Attributes["depthLimitNulls"]}
	}
	return result, nil
}

// This entire file also runs from an isolated external module. Keep imports and
// setup portable: no internal packages, private methods, or repository key paths.
func TestE2EClaimsEnrichmentLogin(t *testing.T) {
	const secret = "synthetic-claims-enrichment-signing-key-for-tests-only"
	const password = "SyntheticEnrichmentPassword123!"
	srv := httptest.NewUnstartedServer(nil)
	t.Cleanup(srv.Close)
	origin := "https://" + srv.Listener.Addr().String()
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: password, Roles: []string{"viewer"}}}); err != nil {
		t.Fatal("provision user failed")
	}
	var stores []ids.IdentityStore
	var transforms []*transformerconfig.Config
	var immutableID string
	for _, realm := range []string{"north", "south"} {
		store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: realm, Kind: "local", Params: map[string]any{"path": dbPath, "realm": realm}}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Configure(); err != nil {
			t.Fatal(err)
		}
		rr := &requests.Request{User: requests.User{Username: "alice"}}
		if err := store.Request(operator.IdentifyUser, rr); err != nil || rr.Authentication.UserID == "" {
			t.Fatal("immutable account lookup failed")
		}
		immutableID = rr.Authentication.UserID
		// These fixture-only issuance mappings bind the single provisioned account's
		// actual database ID. Production hosts must preserve that immutable binding
		// across account deletion/recreation and must not derive it from a display name.
		transform, err := transformerparser.NewUserTransformerConfigFromDirectives([]string{
			"match realm " + realm, "exact match sub alice",
			cfgutil.EncodeArgs([]string{"add", "directory_id", immutableID, "as", "string"}),
			"add tenant " + realm + " as string", "add aud api",
			"overwrite sub same-display-name", "overwrite email shared@example.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		transforms = append(transforms, transform)
		stores = append(stores, store)
	}
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "enrichment", IdentityStores: []string{"north", "south"}, CookieConfig: cookie.NewConfig(), UserTransformerConfigs: transforms, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + secret}}, Logger: zap.NewNop(), IdentityStores: stores})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(portal.Close)
	identityKey := enrichment.Identity{Issuer: origin + "/auth/login", Realm: "north", Subject: immutableID, Tenant: "north"}
	backendConfig, err := staticparser.NewStaticClaimsEnrichmentConfigFromDirectives([]string{
		"claim foo bar",
		cfgutil.EncodeArgs([]string{"claim", "permissions", "json", `["read","write"]`}),
		cfgutil.EncodeArgs([]string{"claim", "featureFlags", "json", `{"active":true,"limits":[5,10],"detail":{"note":"literal"}}`}),
		"claim enabled json true", "claim quota json 9007199254740993", "claim optional json null",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Typed nil maps and slices represent null, including at the container depth
	// limit. Exercise public Go configuration alongside the parsed JSON values.
	var nested any = map[string]any{"array": []any(nil), "strings": []string(nil), "object": map[string]any(nil)}
	for range 15 {
		nested = []any{nested}
	}
	backendConfig.Claims["depthLimitNulls"] = nested
	backend, err := static.New(backendConfig)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := enrichmentparser.NewClaimsEnrichmentConfigFromDirectives([]string{
		"source static", "version v1", cfgutil.EncodeArgs([]string{"issuer", identityKey.Issuer}), "realm north", "subject claim directory_id", "tenant claim tenant", "audience api", "attribute foo string", "attribute permissions string list", "attribute featureFlags json", "attribute enabled json", "attribute quota json", "attribute optional json", "attribute depthLimitNulls json", "timeout 50ms", "max age 5m",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Typed configuration survives serialization before runtime attachment.
	serialized, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	var restored enrichment.Config
	if err := json.Unmarshal(serialized, &restored); err != nil {
		t.Fatal(err)
	}
	field, err := aclparser.NewACLFieldConfigFromDirectives("custom", []string{"claim foo", "type string"})
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := aclparser.NewACLFieldConfigFromDirectives("permission", []string{"claim permissions", "type string list"})
	if err != nil {
		t.Fatal(err)
	}
	cancelStarted, cancelObserved := make(chan struct{}), make(chan struct{})
	gates := make(map[string]*authz.Gatekeeper)
	for _, mode := range []string{"normal", "unattached", "outage", "timeout", "cancel", "allow-stop", "missing", "literal", "expired", "reserved", "wrong-type", "too-deep"} {
		var source enrichment.Backend = backend
		selectedBinding := restored
		if mode != "normal" && mode != "unattached" {
			fixture := &responseBackend{next: source, mode: mode}
			if mode == "cancel" {
				selectedBinding.Timeout = "30s"
				fixture.started, fixture.canceled = cancelStarted, cancelObserved
			}
			source = fixture
		}
		enricher, err := enrichment.New(&selectedBinding, source)
		if err != nil {
			t.Fatal(err)
		}
		fields := []*acl.FieldConfig{field, permissions}
		if mode == "wrong-type" {
			jsonField, err := aclparser.NewACLFieldConfigFromDirectives("json_value", []string{"claim featureFlags", "type string"})
			if err != nil {
				t.Fatal(err)
			}
			fields = append(fields, jsonField)
		}
		conditions := []string{"match roles viewer", "match custom bar", "match permission read", "match method GET", "prefix match path /private/"}
		if mode == "wrong-type" {
			conditions = append(conditions, "match json_value false")
		}
		if mode == "allow-stop" {
			conditions = []string{"match any"}
		}
		gate, err := authz.NewGatekeeper(&authz.PolicyConfig{Name: mode, AuthRedirectDisabled: true, ValidateBearerHeader: true, ValidateMethodPath: true, PassClaimsWithHeaders: true, RawCryptoKeyStoreConfig: []string{"crypto key verify " + secret}, AccessListFields: fields, AccessListRules: []*acl.RuleConfiguration{{Conditions: conditions, Action: "allow stop"}}}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(gate.Close)
		if mode != "unattached" {
			if err := gate.SetClaimsEnricher(enricher); err != nil {
				t.Fatal(err)
			}
		}
		if err := gate.SetClaimsEnricher(nil); err == nil {
			t.Fatal("nil attachment silently disabled enrichment")
		}
		gates[mode] = gate
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth/") {
			_ = portal.ServeHTTP(r.Context(), w, r, requests.NewRequest())
			return
		}
		mode := r.Header.Get("X-Fixture-Mode")
		if mode == "" {
			mode = "normal"
		}
		gate := gates[mode]
		if gate == nil {
			http.Error(w, "unknown fixture mode", 400)
			return
		}
		ar := requests.NewAuthorizationRequest()
		err := gate.Authenticate(w, r, ar)
		if !ar.Response.Authorized {
			if err == nil {
				http.Error(w, "denied", 403)
			}
			return
		}
		w.Header().Set("X-Upstream-Roles", r.Header.Get("X-Token-User-Roles"))
		w.WriteHeader(http.StatusNoContent)
	})
	srv.StartTLS()
	client := srv.Client()
	client.Timeout = 5 * time.Second
	login := func(realm string) string {
		t.Helper()
		loginClient, err := authclient.NewClient(&authclient.Config{BaseURL: origin + "/auth", Realm: realm, Username: "alice", Password: password}, authclient.Options{HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := loginClient.Authenticate(t.Context())
		if err != nil || credentials == nil || credentials.AccessToken == "" {
			t.Fatal("real TLS password login failed")
		}
		return credentials.AccessToken
	}
	token := login("north")
	otherTenantToken := login("south")
	request := func(token, mode, method, path string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, origin+path, nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Fixture-Mode", mode)
		req.Header.Set("X-Token-User-Roles", "admin")
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != want {
			t.Errorf("%s %s (%s): HTTP %d, want %d", method, path, mode, resp.StatusCode, want)
		}
		if want == 204 && strings.Contains(resp.Header.Get("X-Upstream-Roles"), "admin") {
			t.Error("enrichment changed canonical roles")
		}
	}
	request(token, "", http.MethodGet, "/private/read", 204)
	request(token, "", http.MethodGet, "/private/read", 204) // Real gatekeeper cache hit.
	// Reject a malformed replacement through the public parser, preserving the
	// active backend and its authorization behavior.
	badDirective := cfgutil.EncodeArgs([]string{"claim", "foo", "json", "{\"invalid-\xff\":true}"})
	if candidate, err := staticparser.NewStaticClaimsEnrichmentConfigFromDirectives([]string{badDirective}); err == nil || candidate != nil {
		t.Fatal("malformed replacement configuration accepted")
	}
	request(token, "", http.MethodGet, "/private/read", 204)
	request(otherTenantToken, "", http.MethodGet, "/private/read", 403)
	request(token, "", http.MethodPost, "/private/read", 403)
	request(token, "", http.MethodGet, "/outside", 403)
	request(token, "outage", http.MethodGet, "/private/read", 403)
	request(token, "timeout", http.MethodGet, "/private/read", 403)
	request(token, "allow-stop", http.MethodGet, "/private/read", 403)
	for _, mode := range []string{"unattached", "missing", "literal", "expired", "reserved", "wrong-type", "too-deep"} {
		request(token, mode, http.MethodGet, "/private/read", 403)
	}
	// Cancel only after lookup begins, proving the gatekeeper forwards the actual
	// HTTP request context instead of waiting for the independent 30s policy timer.
	cancelCtx, cancelRequest := context.WithCancel(t.Context())
	defer cancelRequest()
	cancelReq, err := http.NewRequestWithContext(cancelCtx, http.MethodGet, origin+"/private/read", nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelReq.Header.Set("Authorization", "Bearer "+token)
	cancelReq.Header.Set("X-Fixture-Mode", "cancel")
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, err := client.Do(cancelReq)
		if err == nil {
			response.Body.Close()
		}
	}()
	select {
	case <-cancelStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelable lookup did not start")
	}
	cancelRequest()
	select {
	case <-cancelObserved:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not observe HTTP cancellation")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled client request did not finish")
	}

	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() { request(token, "", http.MethodGet, "/private/read", 204) })
	}
	wg.Wait()
}
