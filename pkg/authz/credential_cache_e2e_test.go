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

package authz_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This legacy, cacheable authenticator deliberately supports Basic only.
type cacheMethodAuthenticator struct{}

func (*cacheMethodAuthenticator) GetName() string { return "method-fixture" }
func (*cacheMethodAuthenticator) BasicAuth(r *authproxy.Request) error {
	if r.Secret != base64.StdEncoding.EncodeToString([]byte("alice:password")) {
		return fmt.Errorf("denied")
	}
	data, err := json.Marshal(map[string]any{"sub": "alice", "email": "alice@example.test", "roles": []string{"viewer"}, "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		return err
	}
	r.Response = authproxy.Response{Name: "access_token", IsPlainPayload: true, Payload: string(data)}
	return nil
}
func (*cacheMethodAuthenticator) APIKeyAuth(*authproxy.Request) error { return fmt.Errorf("denied") }
func TestE2ECredentialCacheSeparatesMethods(t *testing.T) {
	gate, err := authz.NewGatekeeper(&authz.PolicyConfig{Name: "credential-methods", AuthRedirectDisabled: true,
		RawCryptoKeyStoreConfig: []string{"crypto key verify synthetic-credential-cache-method-regression-0123456789"},
		AuthProxyRawConfig:      []string{"basic auth realm staff portal method-fixture", "api key auth realm staff portal method-fixture"},
		AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.AddAuthenticators([]authproxy.Authenticator{&cacheMethodAuthenticator{}}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := requests.NewAuthorizationRequest()
		if gate.Authenticate(w, r, ar) != nil || !ar.Response.Authorized {
			http.Error(w, "denied", 401)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	for _, method := range []string{"basic", "basic", "api", "basic"} {
		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		secret := base64.StdEncoding.EncodeToString([]byte("alice:password"))
		req.Header.Set("X-Auth-Realm", "staff")
		want := 204
		if method == "basic" {
			req.Header.Set("Authorization", "Basic "+secret)
		} else {
			want = 401
			req.Header.Set("X-API-Key", secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("method=%s status=%d want=%d", method, resp.StatusCode, want)
		}
	}
}
