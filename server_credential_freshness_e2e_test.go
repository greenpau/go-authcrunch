// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authcrunch_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
)

// The embedding host attaches portals through the public root constructor.
// Account mutations use the real authenticated admin/profile HTTP APIs; the
// protected requests have no browser jar and reuse the same credentials.
func TestE2EServerPortalCredentialFreshness(t *testing.T) {
	f := newServerCompositionFixture(t, false, func(cfg *authcrunch.Config) {
		cfg.IdentityStores = cfg.IdentityStores[:1]
		portal := cfg.AuthenticationPortals[0]
		portal.IdentityStores = []string{"local"}
		portal.RefreshTokens = nil
		portal.OIDCProvider = nil
		cfg.AuthorizationPolicies[0].AuthProxyRawConfig = []string{
			"basic auth realm local portal portal", "api key auth realm local portal portal",
		}
	})
	plain := *f.client
	plain.Jar = nil
	request := func(step string, client *http.Client, method, target, body string, headers http.Header, want int) compositionResponse {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: construct request", step)
		}
		maps.Copy(r.Header, headers)
		response, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s: HTTP request failed", step)
		}
		defer response.Body.Close()
		if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatalf("%s: TLS was not independently verified", step)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			t.Fatalf("%s: invalid bounded response body", step)
		}
		if response.StatusCode != want {
			t.Fatalf("%s: HTTP %d, want %d", step, response.StatusCode, want)
		}
		return compositionResponse{status: response.StatusCode, header: response.Header, body: data}
	}
	jsonRequest := func(step, path string, payload map[string]any) map[string]any {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("%s: encode JSON", step)
		}
		response := request(step, f.client, http.MethodPost, f.issuer+path, string(body), http.Header{
			"Content-Type": {"application/json"}, "Origin": {f.origin},
		}, http.StatusOK)
		if response.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: missing no-store response policy", step)
		}
		var result map[string]any
		if json.Unmarshal(response.body, &result) != nil {
			t.Fatalf("%s: malformed JSON response", step)
		}
		return result
	}
	f.login(t, "local", "alice")
	cookieURL, err := url.Parse(f.issuer + "/portal")
	if err != nil {
		t.Fatal("invalid fixture issuer")
	}
	var bearer string
	for _, c := range f.client.Jar.Cookies(cookieURL) {
		if c.Name == "AUTHP_ACCESS_TOKEN" {
			bearer = c.Value
		}
	}
	if bearer == "" {
		t.Fatal("browser login omitted access token")
	}
	f.verify(t, bearer, "/.well-known/jwks.json")
	const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	created := jsonRequest("enroll owner API key", "/api/profile", map[string]any{
		"kind": "add_user_api_key", "title": "FreshnessKey", "description": "", "content": apiKey,
	})
	if created["entry"] != "Created" {
		t.Fatal("profile API did not enroll the key")
	}
	f.login(t, "local", "admin")
	admin := func(operation string, fields map[string]any) {
		t.Helper()
		user := map[string]any{"username": "alice", "email": "alice@example.test"}
		maps.Copy(user, fields)
		result := jsonRequest("administrator "+operation, "/api/server/user", map[string]any{
			"realm": "local", "operation": operation, "user": user,
		})
		if result["status"] != "success" {
			t.Fatalf("administrator %s did not commit mutation", operation)
		}
	}
	protected := func(step, method string, want int) {
		t.Helper()
		headers := http.Header{"X-Auth-Realm": {"local"}}
		switch method {
		case "basic":
			headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:"+tests.TestPwd1)))
		case "api_key":
			headers.Set("X-API-Key", apiKey)
		case "bearer":
			headers.Set("Authorization", "Bearer "+bearer)
		default:
			t.Fatal("unknown fixture credential method")
		}
		request(step+" "+method, &plain, http.MethodGet, f.origin+"/protected", "", headers, want)
	}
	for range 2 {
		for _, method := range []string{"basic", "api_key", "bearer"} {
			protected("unchanged credentials", method, http.StatusNoContent)
		}
	}
	admin("disable", nil)
	protected("disabled current account", "basic", http.StatusUnauthorized)
	protected("disabled current account", "api_key", http.StatusUnauthorized)
	// Bearer tokens are a separate, stateless credential source. This change
	// must not turn their cache into a live account-status check.
	protected("previously issued bearer retains its lifetime", "bearer", http.StatusNoContent)
	admin("enable", nil)
	protected("re-enabled current account", "basic", http.StatusNoContent)
	protected("re-enabled current account", "api_key", http.StatusNoContent)
	admin("overwrite_auth_challenges", map[string]any{"challenges": []string{"password"}})
	protected("API key cannot satisfy current explicit password policy", "api_key", http.StatusUnauthorized)
	protected("password satisfies current explicit password policy", "basic", http.StatusNoContent)
	admin("reset_password", nil)
	protected("previously valid password was revoked", "basic", http.StatusUnauthorized)
}
