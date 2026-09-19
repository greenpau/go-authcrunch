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

package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAuthenticationChallengeAPIKeyRequestContext(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	const secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	if err := f.store.Request(operator.AddAPIKey, &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1}, Key: requests.Key{Payload: secret, Usage: "api", Comment: "HTTP policy context"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, issuer           string
		proxy, cancel, allowed bool
	}{
		{name: "matching HTTP issuer", issuer: "https://portal.example.test/auth/login"},
		{name: "query is not policy context", issuer: "https://portal.example.test/auth/login?ignored=yes", allowed: true},
		{name: "other issuer", issuer: "https://other.example.test/auth/login", allowed: true},
		{name: "HTTP does not use proxy issuer", issuer: "authp", allowed: true},
		{name: "proxy issuer preserved", issuer: "authp", proxy: true},
		{name: "proxy has no HTTP issuer", issuer: "https://portal.example.test/auth/login", proxy: true, allowed: true},
		{name: "cancelled HTTP request", issuer: "unmatched", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := transformerparser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "exact match iss " + tc.issuer, "require totp"})
			if err != nil {
				t.Fatal(err)
			}
			f.portal.transformer, err = transformer.NewFactory([]*transformer.Config{cfg})
			if err != nil {
				t.Fatal(err)
			}
			if tc.proxy {
				req := &authproxy.Request{Realm: "local", Secret: secret}
				err := f.portal.APIKeyAuth(req)
				if (err == nil) != tc.allowed || (req.Response.Payload != "") != tc.allowed {
					t.Fatal("proxy issuer policy changed", err)
				}
				return
			}
			ctx := t.Context()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			request := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://portal.example.test/auth/login?ignored=yes", nil)
			response := httptest.NewRecorder()
			if err := f.portal.handleJSONAPIKeyLogin(ctx, response, request, &apiauth.AuthRequest{Realm: "local", APIKey: secret}); err != nil {
				t.Fatal(err)
			}
			var result apiauth.AuthResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (response.Code == http.StatusOK) != tc.allowed || result.Authenticated != tc.allowed || (result.AccessToken != "") != tc.allowed {
				t.Fatalf("HTTP context policy returned %d, allowed=%t", response.Code, tc.allowed)
			}
		})
	}
}
