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
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

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
