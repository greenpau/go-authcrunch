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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	bindingparser "github.com/greenpau/go-authcrunch/pkg/authz/external/parser"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
	httpparser "github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson/parser"
)

func TestE2EServerExternalAuthorizationOAuth(t *testing.T) {
	f := newDirectOAuthFixture(t)
	var deny atomic.Bool
	var calls atomic.Int64
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var input external.Request
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&input) != nil {
			t.Error("invalid external request")
			return
		}
		if input.Identity.Subject != "alice" || input.Identity.Realm != "company" || input.Identity.Issuer != f.server.URL || input.Resource != "/private/report" || input.Action != "GET" {
			t.Error("OAuth decision lost original identity or resource")
		}
		decision := "allow"
		if deny.Load() {
			decision = "deny"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(external.Result{Decision: decision, Policy: input.Policy, Version: input.Version})
	}))
	defer service.Close()
	cfg, err := httpparser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{"endpoint " + service.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := httpjson.New(cfg, service.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	binding, err := bindingparser.NewExternalAuthorizationConfigFromDirectives([]string{"policy primary", "version v1", "issuer " + f.server.URL, "realm company"})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := external.New(binding, backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.gatekeepers["primary"].SetExternalAuthorizer(authorizer); err != nil {
		t.Fatal(err)
	}
	// Deny the original resource at callback time: no session may be issued.
	deny.Store(true)
	callback := f.callback(t, f.client, "/private/report")
	completed := f.request(t, f.client, "GET", callback, nil)
	directOAuthStatus(t, completed, 403)
	for _, cookie := range completed.cookies {
		if cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("denied callback issued session")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("callback bypassed required decision")
	}
	deny.Store(false)
	callback = f.callback(t, f.client, "/private/report")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	for _, denied := range []bool{false, true, false} {
		deny.Store(denied)
		prior := calls.Load()
		result := f.request(t, f.client, "GET", "/private/report", nil)
		want := 200
		if denied {
			want = 403
		}
		directOAuthStatus(t, result, want)
		if calls.Load() != prior+1 {
			t.Fatal("session reused authorization decision")
		}
		if denied && len(result.body) > 0 && json.Valid(result.body) {
			t.Fatal("denied session reached application")
		}
	}
	prior := calls.Load()
	directOAuthStatus(t, f.request(t, f.client, "GET", "/admin", nil), 403)
	if calls.Load() != prior {
		t.Fatal("local denial reached external service")
	}
	service.Close()
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private/report", nil), 403)
	// The original fixture returns JSON only after gatekeeper authorization.
	response := f.request(t, f.client, "GET", "/public", nil)
	directOAuthStatus(t, response, 200)
	var body map[string]any
	if json.Unmarshal(response.body, &body) != nil || body["bypassed"] != true {
		t.Fatal("explicit public bypass changed")
	}
}
