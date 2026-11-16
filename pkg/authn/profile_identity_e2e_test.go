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
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Preserve the authenticated operation contracts of an older injected store,
// while intentionally omitting the newly optional capability metadata method.
type legacyProfileE2EStore struct {
	ids.IdentityStore
	ids.IdentityRequestStore
}

func (s *legacyProfileE2EStore) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	return s.IdentityStore.(interface {
		WithRefreshIdentity(context.Context, requests.AuthenticationEvidence, func(identity.RefreshIdentity) error) error
	}).WithRefreshIdentity(ctx, proof, apply)
}

// Metadata can survive a host adapter even when its operation interface does
// not. The portal must inspect both before advertising usable profile support.
type metadataProfileE2EStore struct {
	ids.IdentityStore
	passwordOnly bool
}

func (s *metadataProfileE2EStore) GetCapabilities() identity.StoreCapabilities {
	if s.passwordOnly {
		return identity.StoreCapabilities{PasswordChange: true}
	}
	return identity.StoreCapabilities{ProfileRead: true}
}

func (s *metadataProfileE2EStore) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	return s.IdentityStore.(interface {
		WithRefreshIdentity(context.Context, requests.AuthenticationEvidence, func(identity.RefreshIdentity) error) error
	}).WithRefreshIdentity(ctx, proof, apply)
}

type boundMetadataProfileE2EStore struct {
	*metadataProfileE2EStore
	ids.IdentityRequestStore
}

func TestE2EProfilePasswordOnlyCapabilities(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", false, func(c *authn.PortalConfig) { c.API.ProfileEnabled = true })
	f.mu.Lock()
	f.portal.Close()
	f.store = &boundMetadataProfileE2EStore{
		metadataProfileE2EStore: &metadataProfileE2EStore{IdentityStore: f.store, passwordOnly: true},
		IdentityRequestStore:    f.store.(ids.IdentityRequestStore),
	}
	f.portal = f.newPortal()
	f.mu.Unlock()
	token := f.login(t, "alice")
	caps := sqlitePortalRequest(t, f, token, "GET", "/api/capabilities", nil, http.StatusOK)
	profile := caps["profile"].(map[string]any)
	if profile["supported"] != true || profile["allowed"] != true || profile["reason"] != "available" {
		t.Error("working password operation was advertised as unsupported")
	}
	sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, http.StatusNotImplemented)
	sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{
		"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": tests.TestPwd2,
	}, http.StatusOK)
	client := *f.client
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	browser := &oidcE2EFixture{server: f.server, client: &client, issuer: f.server.URL + "/auth"}
	webAuthnEnrollmentLogin(t, browser, "alice", tests.TestPwd2)
	fresh := loginIdentityCookie(browser, "AUTHP_ACCESS_TOKEN")
	if fresh == "" || fresh == token {
		t.Fatal("changed password did not establish a fresh real login")
	}
	sqlitePortalRequest(t, f, fresh, "GET", "/api/capabilities", nil, http.StatusOK)
}

func TestE2EProfileDeclaredCapabilities(t *testing.T) {
	for _, name := range []string{"metadata_only", "bound_operations"} {
		t.Run(name, func(t *testing.T) {
			bound := name == "bound_operations"
			f := newDocumentsE2E(t, "/auth", false, func(c *authn.PortalConfig) { c.API.ProfileEnabled = true })
			f.mu.Lock()
			f.portal.Close()
			metadata := &metadataProfileE2EStore{IdentityStore: f.store}
			if bound {
				f.store = &boundMetadataProfileE2EStore{metadataProfileE2EStore: metadata, IdentityRequestStore: f.store.(ids.IdentityRequestStore)}
			} else {
				f.store = metadata
			}
			f.portal = f.newPortal()
			f.mu.Unlock()
			token := f.login(t, "alice")
			caps := sqlitePortalRequest(t, f, token, "GET", "/api/capabilities", nil, http.StatusOK)
			profile := caps["profile"].(map[string]any)
			if profile["supported"] != bound || profile["allowed"] != bound {
				t.Error("metadata alone was treated as bound profile operations")
			}
			want := http.StatusNotImplemented
			if bound {
				want = http.StatusOK
			}
			response := sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_dashboard_data"}, want)
			if !bound {
				if profile["reason"] != "unsupported_capability" || response["code"] != "unsupported_capability" {
					t.Error("discovery and the profile refusal disagree")
				}
				return
			}
			entry := response["entry"].(map[string]any)
			if len(entry["asset_count"].(map[string]any)) != 0 {
				t.Fatal("partial provider advertised undeclared collections")
			}
			for _, declaration := range []map[string]any{caps["store"].(map[string]any), entry["capabilities"].(map[string]any)} {
				if operations, ok := declaration["admin_operations"].([]any); !ok || len(operations) != 0 {
					t.Error("missing admin operations must serialize as an empty array")
				}
			}
			sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_info"}, http.StatusOK)
			sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_api_keys"}, http.StatusNotImplemented)
		})
	}
}

func TestE2EProfileLegacyStoreDashboard(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", false, func(config *authn.PortalConfig) { config.API.ProfileEnabled = true })
	f.mu.Lock()
	f.portal.Close()
	f.store = &legacyProfileE2EStore{IdentityStore: f.store, IdentityRequestStore: f.store.(ids.IdentityRequestStore)}
	f.portal = f.newPortal()
	f.mu.Unlock()
	token := f.login(t, "alice")
	sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_future_credentials"}, http.StatusBadRequest)
	sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]any{
		"kind": "add_user_api_key", "title": "LegacyKey", "description": "legacy store dashboard", "content": strings.Repeat("Abcd1234", 8),
	}, http.StatusOK)
	result := sqlitePortalRequest(t, f, token, "POST", "/api/profile", map[string]string{"kind": "fetch_user_dashboard_data"}, http.StatusOK)
	entry := result["entry"].(map[string]any)
	counts := entry["asset_count"].(map[string]any)
	for name, want := range map[string]float64{"api_key": 1, "ssh_key": 0, "gpg_key": 0, "mfa_2fa": 0} {
		if got, ok := counts[name]; !ok || got != want {
			t.Errorf("legacy dashboard count %s = %v, want %v", name, got, want)
		}
	}
	if _, declared := entry["capabilities"]; declared {
		t.Error("legacy store was given a fabricated capability declaration")
	}
	// The old profile interface remains usable without claiming support in the
	// new discovery response when the store has no declared capability metadata.
	response := sqlitePortalRequest(t, f, token, "GET", "/api/capabilities", nil, http.StatusOK)
	data, err := json.Marshal(response)
	if err != nil || strings.Contains(string(data), "LegacyKey") {
		t.Fatal("capability response exposed credential inventory")
	}
}

func TestE2EProfileRejectsReplacedSessionToken(t *testing.T) {
	f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs = nil
	})
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	previous := loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/login?fresh=1", nil, nil), http.StatusOK)
	webAuthnEnrollmentLogin(t, f, "bob", tests.TestPwd2)
	current := loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
	firstBob := current
	firstClaims := loginIdentityClaims(t, f, firstBob, "bob")
	bobID, _ := firstClaims["id"].(string)
	if bobID == "" {
		t.Fatal("local login did not carry immutable identity")
	}
	if err := store.RevokeUserSessions(t.Context(), bobID); err != nil {
		t.Fatal(err)
	}
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/login?fresh=1", nil, nil), http.StatusOK)
	webAuthnEnrollmentLogin(t, f, "bob", tests.TestPwd2)
	current = loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
	nextClaims := loginIdentityClaims(t, f, current, "bob")
	if firstClaims["nonce"] == nil || firstClaims["nonce"] == "" || nextClaims["nonce"] == nil || nextClaims["nonce"] == "" || firstClaims["nonce"] == nextClaims["nonce"] {
		t.Fatal("fresh local login reused its access nonce")
	}
	client := *f.client
	client.Jar = nil
	native := &oidcE2EFixture{server: f.server, client: &client, issuer: f.issuer}
	for _, path := range []string{"/portal", "/apps/mobile-access", "/apps/sso/example/metadata.xml"} {
		t.Run("replaced token "+path, func(t *testing.T) {
			oidcE2EStatus(t, native.request(t, http.MethodGet, path, nil, http.Header{"Authorization": {"Bearer " + previous}}), http.StatusFound)
		})
	}
	for _, path := range []string{"/portal", "/apps/mobile-access"} {
		t.Run("current token "+path, func(t *testing.T) {
			oidcE2EStatus(t, native.request(t, http.MethodGet, path, nil, http.Header{"Authorization": {"Bearer " + current}}), http.StatusOK)
		})
	}
	body := map[string]any{"kind": "add_user_api_key", "title": "SessionKey", "description": "replaced session regression", "content": strings.Repeat("Abcd5678", 8)}
	oidcE2EStatus(t, native.jsonRequest(t, "/api/profile", body, previous), http.StatusUnauthorized)
	oidcE2EStatus(t, native.jsonRequest(t, "/api/profile", body, firstBob), http.StatusUnauthorized)
	for _, name := range []string{"alice", "bob"} {
		lookup := &requests.Request{User: requests.User{Username: name, Email: name + "@example.test"}, Key: requests.Key{Usage: "api"}}
		if err := store.Request(operator.GetAPIKeys, lookup); err != nil {
			t.Fatal(err)
		}
		if len(lookup.Response.Payload.(*identity.APIKeyBundle).Get()) != 0 {
			t.Fatal("replaced token persisted a credential")
		}
	}
	oidcE2EStatus(t, native.jsonRequest(t, "/api/profile", body, current), http.StatusOK)
}

func TestE2EProfileCredentialMutationUsesCanonicalIdentity(t *testing.T) {
	f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs[0].Actions = []string{"overwrite sub bob", "overwrite email bob@example.test"}
	})
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "bob")
	response := f.jsonRequest(t, "/api/profile", map[string]any{
		"kind": "add_user_api_key", "title": "ProfileKey", "description": "profile identity regression",
		"content": strings.Repeat("Abcd1234", 8),
	}, "", http.Header{"Origin": {f.server.URL}})
	oidcE2EStatus(t, response, http.StatusOK)
	for _, name := range []string{"alice", "bob"} {
		lookup := &requests.Request{User: requests.User{Username: name, Email: name + "@example.test"}, Key: requests.Key{Usage: "api"}}
		if err := store.Request(operator.GetAPIKeys, lookup); err != nil {
			t.Fatal(err)
		}
		got := len(lookup.Response.Payload.(*identity.APIKeyBundle).Get())
		want := 0
		if name == "alice" {
			want = 1
		}
		if got != want {
			t.Errorf("%s credential count = %d, want %d", name, got, want)
		}
	}
}

func TestE2EProfileRejectsRevokedSession(t *testing.T) {
	f, store, userID := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs = nil
	})
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	if err := store.RevokeUserSessions(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	response := f.jsonRequest(t, "/api/profile", map[string]any{
		"kind": "add_user_api_key", "title": "RevokedSessionKey", "description": "revoked session regression",
		"content": strings.Repeat("Abcd5678", 8),
	}, "", http.Header{"Origin": {f.server.URL}})
	if response.status < 400 {
		t.Errorf("revoked profile session created credential: HTTP %d", response.status)
	}
	lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Usage: "api"}}
	if err := store.Request(operator.GetAPIKeys, lookup); err != nil {
		t.Fatal(err)
	}
	if len(lookup.Response.Payload.(*identity.APIKeyBundle).Get()) != 0 {
		t.Fatal("revoked profile session persisted a credential")
	}
}

func TestE2EProfileRejectsCrossOriginCredentialMutation(t *testing.T) {
	f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs = nil
	})
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	response := f.jsonRequest(t, "/api/profile", map[string]any{
		"kind": "add_user_api_key", "title": "CrossOriginKey", "description": "cross origin regression",
		"content": strings.Repeat("Abcd9876", 8),
	}, "", http.Header{"Origin": {"https://untrusted.example.test"}, "Sec-Fetch-Site": {"same-site"}, "Content-Type": {"text/plain"}})
	if response.status < 400 {
		t.Errorf("cross-origin cookie request created credential: HTTP %d", response.status)
	}
	lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Usage: "api"}}
	if err := store.Request(operator.GetAPIKeys, lookup); err != nil {
		t.Fatal(err)
	}
	if len(lookup.Response.Payload.(*identity.APIKeyBundle).Get()) != 0 {
		t.Fatal("cross-origin request persisted a credential")
	}
}

func TestE2EProfileRequiresJSONAndSupportsNativeRequests(t *testing.T) {
	f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs = nil
	})
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	body := map[string]any{
		"kind": "add_user_api_key", "title": "NativeProfileKey", "description": "native profile regression",
		"content": strings.Repeat("Abcd5432", 8),
	}
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "", "malformed;="} {
		denied := f.jsonRequest(t, "/api/profile", body, "", http.Header{"Origin": {f.server.URL}, "Content-Type": {contentType}})
		oidcE2EStatus(t, denied, http.StatusUnsupportedMediaType)
	}
	lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Usage: "api"}}
	if err := store.Request(operator.GetAPIKeys, lookup); err != nil {
		t.Fatal(err)
	}
	if len(lookup.Response.Payload.(*identity.APIKeyBundle).Get()) != 0 {
		t.Fatal("non-JSON profile request persisted a credential")
	}
	native := replacementClientWithoutJar(f)
	accepted := native.jsonRequest(t, "/api/profile", body, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"))
	oidcE2EStatus(t, accepted, http.StatusOK)
	if err := store.Request(operator.GetAPIKeys, lookup); err != nil {
		t.Fatal(err)
	}
	if len(lookup.Response.Payload.(*identity.APIKeyBundle).Get()) != 1 {
		t.Fatal("authenticated native JSON request did not persist its credential")
	}
}
