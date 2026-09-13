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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func cookieGatekeeper(t *testing.T, sessionName, accessName string) *Gatekeeper {
	t.Helper()
	var accessNames []string
	if accessName != "" {
		accessNames = []string{accessName}
	}
	g, err := NewGatekeeper(&PolicyConfig{Name: "cookies", AuthURLPath: "/login", SessionIDCookieName: sessionName, AccessTokenCookieNames: accessNames, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}, RawCryptoKeyStoreConfig: []string{"crypto key verify " + testutils.GetSharedKey()}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGatekeeperSessionCookieNames(t *testing.T) {
	for _, name := range []string{"", "CUSTOM_SESSION", "SESSION_ID"} {
		g := cookieGatekeeper(t, name, "AUTHP_ACCESS_TOKEN")
		want := name
		if want == "" {
			want = "AUTHP_SESSION_ID"
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: want, Value: "syntheticsession"})
		ar := requests.NewAuthorizationRequest()
		g.parseSessionID(r, ar)
		if ar.SessionID != "syntheticsession" {
			t.Fatal("gatekeeper did not read the effective session cookie")
		}
	}
}

func TestE2EGatekeeperCookieNames(t *testing.T) {
	for _, tc := range []struct {
		name        string
		directives  []string
		sessionName string
	}{
		{name: "defaults"},
		{name: "prefix", directives: []string{"cookie prefix PORTAL"}, sessionName: "PORTAL_SESSION_ID"},
		{name: "explicit", directives: []string{"cookie session id name CUSTOM_SESSION"}, sessionName: "CUSTOM_SESSION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := cookieparser.NewCookieConfigFromDirectives(tc.directives)
			if err != nil {
				t.Fatal(err)
			}
			factory, err := cookie.NewFactory(config)
			if err != nil {
				t.Fatal(err)
			}
			accessName := config.AccessTokenCookieName
			if tc.name == "defaults" {
				accessName = ""
			}
			g := cookieGatekeeper(t, tc.sessionName, accessName)
			user := testutils.NewTestUser()
			user.SetRolesClaim([]string{"authp/user"})
			keys, err := testutils.NewTestCryptoKeyStore()
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.SignToken("access_token", "HS512", user); err != nil {
				t.Fatal("could not sign fixture credential")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					w.Header().Add("Set-Cookie", factory.GetSessionIDCookie(r.Host, "syntheticsession"))
					w.Header().Add("Set-Cookie", factory.GetAccessTokenCookie(r.Host, user.Token))
					w.WriteHeader(http.StatusNoContent)
					return
				}
				ar := requests.NewAuthorizationRequest()
				if err := g.Authenticate(w, r, ar); err != nil || !ar.Response.Authorized {
					return
				}
				w.Write([]byte(ar.SessionID))
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 10 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/login", "/protected"} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if path == "/protected" && (response.StatusCode != http.StatusOK || string(body) != "syntheticsession") {
					t.Fatal("factory cookies did not authorize with the same gatekeeper session")
				}
			}
		})
	}
}
