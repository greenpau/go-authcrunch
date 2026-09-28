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
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	aclparser "github.com/greenpau/go-authcrunch/pkg/acl/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EServerAccessListFields(t *testing.T) {
	const secret = "acl-fields-synthetic-signing-secret-for-local-tests-only"
	const rolesKey = "https://example.org/roles"
	const departmentKey = "https://example.org/profile.department|value, literal"
	parse := func(name, key string, list bool) *acl.FieldConfig {
		t.Helper()
		kind := []string{"type", "string"}
		if list {
			kind = append(kind, "list")
		}
		field, err := aclparser.NewACLFieldConfigFromDirectives(name, []string{
			cfgutil.EncodeArgs([]string{"claim", key}), cfgutil.EncodeArgs(kind),
		})
		if err != nil {
			t.Fatal(err)
		}
		return field
	}
	config := &authcrunch.Config{}
	addPolicy := func(name string, flags int, fields []*acl.FieldConfig, rules []*acl.RuleConfiguration) {
		t.Helper()
		policy := &authz.PolicyConfig{
			Name: name, AuthRedirectDisabled: true, ValidateBearerHeader: true,
			ValidateMethodPath: flags&1 != 0, ValidateSourceAddress: flags&2 != 0, ValidateAccessListPathClaim: flags&4 != 0,
			RawCryptoKeyStoreConfig: []string{"crypto key verify " + secret},
			AccessListRules:         rules, PassClaimsWithHeaders: true,
		}
		if err := policy.ConfigureAccessListFields(fields); err != nil {
			t.Fatal(err)
		}
		if err := config.AddAuthorizationPolicy(policy); err != nil {
			t.Fatal(err)
		}
	}
	for flags := range 8 {
		conditions := []string{"match external_roles admin", "match department engineering", "match roles viewer", "match aud api", "match scopes read"}
		if flags&1 != 0 {
			conditions = append(conditions, "match method GET", "prefix match path /private/")
		}
		addPolicy(fmt.Sprint("guard", flags), flags, []*acl.FieldConfig{parse("external_roles", rolesKey, true), parse("department", departmentKey, false)}, []*acl.RuleConfiguration{{Conditions: conditions, Action: "allow stop"}})
	}
	addPolicy("deny-fallback", 0, []*acl.FieldConfig{parse("external_roles", rolesKey, true)}, []*acl.RuleConfiguration{
		{Conditions: []string{"match external_roles blocked"}, Action: "deny stop"},
		{Conditions: []string{"match roles viewer"}, Action: "allow stop"},
	})
	addPolicy("isolated", 0, []*acl.FieldConfig{parse("external_roles", "https://other.example/roles", true)}, []*acl.RuleConfiguration{{Conditions: []string{"match external_roles admin"}, Action: "allow stop"}})
	addPolicy("legacy", 0, nil, []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}})
	serialized, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	// Direct JSON consumers must receive construction errors for malformed ACL
	// configuration without depending on an embedding host's structural checks.
	for _, tc := range []struct {
		name   string
		change func(*authz.PolicyConfig)
	}{
		{"null field", func(p *authz.PolicyConfig) { p.AccessListFields[0] = nil }},
		{"reserved name", func(p *authz.PolicyConfig) { p.AccessListFields[0].Name = "roles" }},
		{"unsupported type", func(p *authz.PolicyConfig) { p.AccessListFields[0].Type = "number" }},
		{"duplicate name", func(p *authz.PolicyConfig) { p.AccessListFields = append(p.AccessListFields, p.AccessListFields[0]) }},
		{"undeclared field", func(p *authz.PolicyConfig) { p.AccessListFields = nil }},
		{"null rule", func(p *authz.PolicyConfig) { p.AccessListRules = []*acl.RuleConfiguration{nil} }},
	} {
		t.Run("reject configuration/"+tc.name, func(t *testing.T) {
			var candidate authcrunch.Config
			if err := json.Unmarshal(serialized, &candidate); err != nil {
				t.Fatal(err)
			}
			tc.change(candidate.AuthorizationPolicies[0])
			runtime, err := authcrunch.NewServer(&candidate, zap.NewNop())
			if runtime != nil {
				if closeErr := runtime.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if err == nil || runtime != nil {
				t.Fatal("invalid ACL configuration constructed a runtime")
			}
		})
	}

	newHost := func(configJSON []byte) (*httptest.Server, *observer.ObservedLogs) {
		t.Helper()
		var restored authcrunch.Config
		if err := json.Unmarshal(configJSON, &restored); err != nil {
			t.Fatal(err)
		}
		core, logs := observer.New(zap.DebugLevel)
		runtime, err := authcrunch.NewServer(&restored, zap.New(core))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := runtime.Close(); err != nil {
				t.Error(err)
			}
		})
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gate, err := runtime.GetGatekeeperByName(r.Header.Get("X-Test-Policy"))
			if err != nil {
				http.Error(w, "unknown policy", http.StatusBadRequest)
				return
			}
			ar := requests.NewAuthorizationRequest()
			response := httptest.NewRecorder()
			err = gate.Authenticate(response, r, ar)
			if !ar.Response.Authorized {
				if err != nil && response.Code == http.StatusOK {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				maps.Copy(w.Header(), response.Header())
				w.WriteHeader(response.Code)
				_, _ = w.Write(response.Body.Bytes())
				return
			}
			w.Header().Set("X-Upstream-Reached", "yes")
			w.Header().Set("X-Upstream-Roles", r.Header.Get("X-Token-User-Roles"))
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		return srv, logs
	}
	srv, logs := newHost(serialized)
	// Sign independently of User and KMS so malformed JSON types reach the real
	// verifier, rather than a fixture normalizing them before signing.
	sign := func(claims map[string]any, key string) string {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS512","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
		mac := hmac.New(sha512.New, []byte(key))
		_, _ = mac.Write([]byte(input))
		return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	claims := map[string]any{
		"sub": "custom-user", "roles": []string{"viewer"}, "aud": "api", "scope": "read write",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"addr": "127.0.0.1", "acl": map[string]any{"paths": []string{"/private/**"}},
		rolesKey: []string{"admin"}, departmentKey: "engineering",
		// These must not replace method/path metadata from the request.
		"method": "GET", "path": "/private/document",
	}
	request := func(host *httptest.Server, policy, method, path, token string, allowed bool) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, host.URL+path, nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Test-Policy", policy)
		client := *host.Client()
		client.Timeout = 5 * time.Second
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if allowed {
			if resp.StatusCode != http.StatusNoContent || resp.Header.Get("X-Upstream-Reached") != "yes" || resp.Header.Get("X-Upstream-Roles") != "viewer" {
				t.Errorf("policy %s: successful request status/headers = %d/%q/%q", policy, resp.StatusCode, resp.Header.Get("X-Upstream-Reached"), resp.Header.Get("X-Upstream-Roles"))
			}
		} else if resp.StatusCode < 400 || resp.StatusCode >= 500 || resp.Header.Get("X-Upstream-Reached") != "" {
			t.Errorf("policy %s: rejected request status = %d, upstream = %q", policy, resp.StatusCode, resp.Header.Get("X-Upstream-Reached"))
		}
	}
	token := sign(claims, secret)
	for flags := range 8 {
		policy := fmt.Sprint("guard", flags)
		t.Run(policy, func(t *testing.T) {
			request(srv, policy, "GET", "/private/document", token, true)
			misses := logs.FilterMessage("cache miss for JWT credentials").Len()
			request(srv, policy, "GET", "/private/document", token, true)
			if logs.FilterMessage("cache miss for JWT credentials").Len() != misses {
				t.Fatal("accepted token was not cached")
			}
			for _, value := range []any{nil, "admin", []any{"admin", 7}, []any{"admin", nil}, []string{}, []string{"reader"}, map[string]any{"role": "admin"}, true} {
				bad := maps.Clone(claims)
				bad[rolesKey] = value
				request(srv, policy, "GET", "/private/document", sign(bad, secret), false)
			}
			missing := maps.Clone(claims)
			delete(missing, rolesKey)
			missing["external_roles"] = []string{"admin"}
			request(srv, policy, "GET", "/private/document", sign(missing, secret), false)
			badDepartment := maps.Clone(claims)
			badDepartment[departmentKey] = []string{"engineering"}
			request(srv, policy, "GET", "/private/document", sign(badDepartment, secret), false)
			if flags&1 != 0 {
				request(srv, policy, "POST", "/private/document", token, false)
			}
			if flags&5 != 0 {
				request(srv, policy, "GET", "/public/document", token, false)
			}
			if flags&2 != 0 {
				bad := maps.Clone(claims)
				bad["addr"] = "192.0.2.9"
				request(srv, policy, "GET", "/private/document", sign(bad, secret), false)
			}
			if flags&4 != 0 {
				bad := maps.Clone(claims)
				bad["acl"] = map[string]any{"paths": []string{"/other/**"}}
				request(srv, policy, "GET", "/private/document", sign(bad, secret), false)
			}
		})
	}
	for _, value := range []any{nil, []any{"allowed", 7}, "allowed", []string{"blocked"}} {
		bad := maps.Clone(claims)
		bad[rolesKey] = value
		request(srv, "deny-fallback", "GET", "/private/document", sign(bad, secret), false)
	}
	request(srv, "deny-fallback", "GET", "/private/document", token, true)
	request(srv, "isolated", "GET", "/private/document", token, false)
	request(srv, "legacy", "GET", "/private/document", token, true)
	request(srv, "guard0", "GET", "/private/document", sign(claims, secret+"wrong"), false)
	expired := maps.Clone(claims)
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	request(srv, "guard0", "GET", "/private/document", sign(expired, secret), false)
	otherClaims := maps.Clone(claims)
	delete(otherClaims, rolesKey)
	otherClaims["https://other.example/roles"] = []string{"admin"}
	otherToken := sign(otherClaims, secret)
	request(srv, "isolated", "GET", "/private/document", otherToken, true)
	request(srv, "guard0", "GET", "/private/document", otherToken, false)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			request(srv, fmt.Sprint("guard", i), "GET", "/private/document", token, true)
			request(srv, "isolated", "GET", "/private/document", token, false)
		})
	}
	wg.Wait()
	// A fresh runtime reconstructed only from persisted configuration supports
	// the same fields, then a changed binding is effective in its replacement.
	if !strings.Contains(string(serialized), `"access_list_fields"`) {
		t.Fatal("field definitions missing from JSON")
	}
	reloaded, _ := newHost(serialized)
	request(reloaded, "guard0", "GET", "/private/document", token, true)
	var changed authcrunch.Config
	if err := json.Unmarshal(serialized, &changed); err != nil {
		t.Fatal(err)
	}
	changed.AuthorizationPolicies[0].AccessListFields[0].Claim = "https://other.example/roles"
	updated, err := json.Marshal(&changed)
	if err != nil {
		t.Fatal(err)
	}
	replacement, _ := newHost(updated)
	request(replacement, "guard0", "GET", "/private/document", token, false)
	request(replacement, "guard0", "GET", "/private/document", otherToken, true)
	request(srv, "guard0", "GET", "/private/document", token, true)
}
