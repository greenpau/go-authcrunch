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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestE2EProviderLoginLogMetadata(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	// The shared public-consumer fixture supplies user_info_fields all and a
	// nested access_token alongside a retained benign label. The real callback
	// reaches this event before snapshot sanitation, not a synthetic log call.
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{logger: zap.New(core)})
	callback, headers := f.login(t, http.StatusSeeOther)
	access := providerRefreshCookie(t, headers, "oauth_portal_token")
	refresh := providerRefreshCookie(t, headers, "AUTHP_REFRESH_TOKEN")
	claims := providerRefreshClaims(t, access)
	info, ok := claims["userinfo"].(map[string]any)
	if !ok {
		t.Fatal("signed provider snapshot omitted the verified UserInfo carrier")
	}
	nested, ok := info["nested"].(map[string]any)
	if !ok || nested["label"] != "retained" {
		t.Fatal("signed provider snapshot did not preserve only the benign nested claim")
	}
	if _, exists := nested["access_token"]; exists {
		t.Fatal("signed provider snapshot retained a nested credential claim")
	}
	response, err := f.client.Get(f.server.URL + "/protected")
	if err != nil {
		t.Fatal("provider log fixture resource request failed")
	}
	resource, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || string(resource) != "protected-resource" {
		t.Fatal("provider log fixture did not authorize over verified TLS")
	}
	status, renewed, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
	if status != http.StatusOK {
		t.Fatalf("provider log fixture renewal returned HTTP %d", status)
	}
	nextAccess := providerRefreshCookie(t, renewed, "oauth_portal_token")
	nextRefresh := providerRefreshCookie(t, renewed, "AUTHP_REFRESH_TOKEN")
	if providerRefreshClaims(t, nextAccess)["sid"] != claims["sid"] || nextRefresh.Value == refresh.Value {
		t.Fatal("logging change altered provider family renewal")
	}
	callbackURL, err := url.Parse(callback)
	if err != nil {
		t.Fatal("provider log fixture callback was invalid")
	}
	status, _, _ = f.send(t, http.MethodGet, callbackURL.RequestURI(), "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("provider log fixture replay returned HTTP %d", status)
	}
	entries := logs.FilterMessage("Successful login").All()
	if len(entries) != 1 {
		t.Fatalf("provider callback, renewal and replay produced %d acceptance events, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	session, sessionOK := fields["session_id"].(string)
	request, requestOK := fields["request_id"].(string)
	if entries[0].Level != zap.InfoLevel || !sessionOK || session == "" || !requestOK || request == "" || fields["auth_method"] != "oauth2" || fields["auth_realm"] != "upstream" {
		t.Fatal("real provider event lost correlation, method or realm metadata")
	}
	if _, exists := fields["user"]; exists {
		t.Fatal("real provider event retained the arbitrary identity payload")
	}
	f.issuer.mu.Lock()
	identity, subject, exchanges, userInfos := f.issuer.lastIdentity, f.issuer.lastSubject, f.issuer.exchanges, f.issuer.userInfos
	f.issuer.mu.Unlock()
	if exchanges != 1 || userInfos != 1 {
		t.Fatal("renewal or replay repeated an upstream authentication exchange")
	}
	secrets := []string{"nested-provider-secret", "synthetic-upstream-refresh-secret", oidcE2EClientSecret, oidcE2EPortalSecret, identity, "opaque-" + subject, access.Value, refresh.Value, nextAccess.Value, nextRefresh.Value, callbackURL.Query().Get("state"), callbackURL.Query().Get("code")}
	for _, entry := range logs.All() {
		encoded, err := json.Marshal(entry.ContextMap())
		if err != nil {
			t.Fatal("provider event fields could not be inspected")
		}
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			quoted, _ := json.Marshal(secret)
			if strings.Contains(entry.Message, secret) || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), string(quoted[1:len(quoted)-1])) {
				t.Fatal("ordinary provider diagnostics exposed a captured credential")
			}
		}
	}
}
