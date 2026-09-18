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

package authz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestStripAuthTokenBySource(t *testing.T) {
	tests := []struct {
		name, target, source, tokenName, token   string
		headers                                  http.Header
		wantAuthorization, wantCookie, wantQuery string
	}{
		{
			name:   "bearer preserves unrelated authorization",
			source: "bearer", tokenName: "bearer", token: "accepted",
			headers:           http.Header{"Authorization": {"Application keep, Bearer accepted"}},
			wantAuthorization: "Application keep",
		},
		{
			name:   "bearer preserves quoted authorization comma",
			source: "bearer", tokenName: "bearer", token: "accepted",
			headers:           http.Header{"Authorization": {`Digest username="a,b", Bearer accepted`}},
			wantAuthorization: `Digest username="a,b"`,
		},
		{
			name:   "named header preserves unrelated authorization",
			source: "header", tokenName: "access_token", token: "accepted",
			headers:           http.Header{"Authorization": {"access_token=accepted", "Application keep"}},
			wantAuthorization: "Application keep",
		},
		{
			name:   "basic removes password credentials",
			source: "basicauth", tokenName: "access_token", token: "cache-key",
			headers:           http.Header{"Authorization": {"Basic YWxpY2U6c2VjcmV0, Application keep"}},
			wantAuthorization: "Application keep",
		},
		{
			name:   "api key removes configured header",
			source: "apiauth", tokenName: "X-Api-Key", token: "cache-key",
			headers: http.Header{"X-Api-Key": {"secret"}, "X-Application": {"keep"}},
		},
		{
			name:   "cookie removes only accepted value",
			source: "cookie", tokenName: "access_token", token: "accepted",
			headers:    http.Header{"Cookie": {"application=keep; access_token=accepted; access_token=other"}},
			wantCookie: "application=keep; access_token=other",
		},
		{
			name:   "cookie removes quoted accepted value",
			source: "cookie", tokenName: "access_token", token: "accepted",
			headers:    http.Header{"Cookie": {`application=keep; access_token="accepted"; access_token=other`}},
			wantCookie: "application=keep; access_token=other",
		},
		{
			name:   "query removes only accepted value",
			target: "/private?application=keep&access_token=accepted&access_token=other",
			source: "query", tokenName: "access_token", token: "accepted",
			wantQuery: "access_token=other&application=keep",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.target
			if target == "" {
				target = "/private"
			}
			r := httptest.NewRequest(http.MethodGet, target, nil)
			r.Header = tc.headers.Clone()
			g := &Gatekeeper{config: &PolicyConfig{StripTokenEnabled: true, APIKeyHeaderName: DefaultAPIKeyHeaderName}}
			g.stripAuthToken(r, &user.User{TokenSource: tc.source, TokenName: tc.tokenName, Token: tc.token})
			if got := strings.TrimSpace(r.Header.Get("Authorization")); got != tc.wantAuthorization {
				t.Fatalf("Authorization=%q, want %q", got, tc.wantAuthorization)
			}
			if got := strings.Join(r.Header.Values("Cookie"), ";"); got != tc.wantCookie {
				t.Fatalf("Cookie=%q, want %q", got, tc.wantCookie)
			}
			if got := r.URL.RawQuery; got != tc.wantQuery {
				t.Fatalf("RawQuery=%q, want %q", got, tc.wantQuery)
			}
			if tc.source == "query" && strings.Contains(r.RequestURI, "accepted") {
				t.Fatalf("RequestURI still contains accepted credential: %q", r.RequestURI)
			}
			if tc.source == "apiauth" && r.Header.Get(DefaultAPIKeyHeaderName) != "" {
				t.Fatal("API key header remains")
			}
		})
	}
}

func TestStripAuthorizationTokenPreservesHeaderFieldLines(t *testing.T) {
	header := http.Header{"Authorization": {
		"Application first",
		"Bearer accepted, Application second",
	}}
	stripAuthorizationToken(header, &user.User{TokenSource: "bearer", Token: "accepted"})
	values := header.Values("Authorization")
	if len(values) != 2 || values[0] != "Application first" || values[1] != "Application second" {
		t.Fatalf("Authorization values=%q", values)
	}
}

func TestStripAuthTokenDisabled(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.Header.Set("Authorization", "Bearer accepted")
	g := &Gatekeeper{config: &PolicyConfig{}}
	g.stripAuthToken(r, &user.User{TokenSource: "bearer", TokenName: "bearer", Token: "accepted"})
	if got := r.Header.Get("Authorization"); got != "Bearer accepted" {
		t.Fatalf("Authorization=%q", got)
	}
}

func TestAuthenticateStripsOwnedHeadersBeforeRejection(t *testing.T) {
	g, err := NewGatekeeper(&PolicyConfig{
		Name: "rejected-header-boundary", AuthRedirectDisabled: true, PassClaimsWithHeaders: true,
		RawCryptoKeyStoreConfig: []string{"crypto key verify " + testutils.GetSharedKey()},
		AccessListRules: []*acl.RuleConfiguration{{
			Conditions: []string{"match roles viewer"}, Action: "allow stop",
		}},
		HeaderInjectionConfigs: []*injector.Config{{Header: "X-Custom-Identity", Field: "email"}},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.Header.Set(claimHeaderUserEmail, "attacker@example.test")
	r.Header.Set("X-Custom-Identity", "attacker@example.test")
	if err := g.Authenticate(httptest.NewRecorder(), r, requests.NewAuthorizationRequest()); err == nil {
		t.Fatal("request without a credential was accepted")
	}
	if r.Header.Get(claimHeaderUserEmail) != "" || r.Header.Get("X-Custom-Identity") != "" {
		t.Fatal("rejected request retained gatekeeper-owned identity headers")
	}
}
