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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAuthenticationChallengeRefreshRequestContext(t *testing.T) {
	f := newRefreshPortal(t, true, true)
	cfg, err := transformerparser.NewUserTransformerConfigFromDirectives([]string{"exact match realm local", "prefix match iss https://", "exact match addr 192.0.2.1", "require auth challenges totp"})
	if err != nil {
		t.Fatal(err)
	}
	f.portal.transformer, err = transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	rr := &requests.Request{User: requests.User{Username: tests.TestUser1}}
	if err := f.store.Request(operator.IdentifyUser, rr); err != nil {
		t.Fatal(err)
	}
	principal := tokenrefresh.Principal{Backend: f.store.GetName(), Realm: "local", Subject: rr.User.Username, UserID: rr.Authentication.UserID, BackendVersion: rr.Authentication.BackendVersion, CredentialVersion: rr.Authentication.CredentialVersion, Challenges: []string{"totp:"}, Methods: []string{"otp"}}
	for _, tc := range []struct {
		name, scheme, address string
		request, allowed      bool
	}{
		{name: "matching request", scheme: "https", address: "192.0.2.1:1234", request: true, allowed: true},
		{name: "changed issuer", scheme: "http", address: "192.0.2.1:1234", request: true},
		{name: "changed address", scheme: "https", address: "198.51.100.20:1234", request: true},
		{name: "missing request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.request {
				r := httptest.NewRequest(http.MethodPost, tc.scheme+"://auth.example.test/auth/api/refresh_token", nil)
				r.RemoteAddr = tc.address
				ctx = context.WithValue(ctx, refreshRequestContextKey{}, r)
			}
			called := false
			err := (&portalRefreshAdapter{portal: f.portal}).WithIdentity(ctx, principal, func(claims map[string]any) error {
				called = true
				if claims["addr"] != "192.0.2.1" || claims["iss"] != "https://auth.example.test/auth/api/refresh_token" {
					t.Fatal("policy evaluation lost current request metadata")
				}
				return nil
			})
			if called != tc.allowed || (err == nil) != tc.allowed || (!tc.allowed && !errors.Is(err, tokenrefresh.ErrDenied)) {
				t.Fatal("unexpected contextual policy result", err)
			}
		})
	}
}
