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
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func oidcProviderE2EDirectives(extra ...string) []string {
	return append([]string{
		"realms local",
		"signing key files ../../testdata/rskeys/test_2_pri.pem",
		"applications trusted-web",
	}, extra...)
}

func TestE2EOIDCProviderDirectiveSettings(t *testing.T) {
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run("mount"+mount, func(t *testing.T) {
			f := newOIDCE2EFixtureWithProviderDirectives(t, mount, false, oidcProviderE2EDirectives(
				"session lifetime 7200", "token lifetime 120", "max sessions 2", "max pending requests 2", "max grants 2"))
			discoveryResponse := f.request(t, "GET", "/.well-known/openid-configuration", nil, nil)
			oidcE2EStatus(t, discoveryResponse, http.StatusOK)
			var discovery map[string]any
			if err := json.Unmarshal(discoveryResponse.body, &discovery); err != nil {
				t.Fatal(err)
			}
			if discovery["issuer"] != f.issuer || discovery["token_endpoint"] != f.issuer+"/oidc/token" {
				t.Fatal("parsed issuer was not served in discovery")
			}
			path := mount
			if path == "" {
				path = "/"
			}
			oidcE2ECookie(t, f.loginBrowser(t), "AUTHP_OIDC_SESSION_ID", path, 7200)
			// A registration in the host map is not automatically enabled here.
			// Nicknames are configuration references, never protocol client IDs.
			for _, id := range []string{"basic", "trusted-web"} {
				response := f.request(t, "GET", "/oidc/authorize?"+f.authorization(id).Encode(), nil, nil)
				oidcE2EStatus(t, response, http.StatusBadRequest)
				if response.header.Get("Location") != "" {
					t.Fatal("unregistered client caused a redirect")
				}
			}
			code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
			tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
			claims := f.verifyIDToken(t, tokens, "second")
			if tokens["expires_in"] != float64(120) || claims["exp"].(float64)-claims["iat"].(float64) != 120 {
				t.Fatal("parsed lifetime did not control access and ID tokens")
			}
			header := http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}}
			info := f.request(t, "GET", "/oidc/userinfo", nil, header)
			oidcE2EStatus(t, info, http.StatusOK)
			var identity map[string]any
			if err := json.Unmarshal(info.body, &identity); err != nil {
				t.Fatal(err)
			}
			if identity["sub"] != claims["sub"] || identity["preferred_username"] != "alice" {
				t.Fatal("selected client lost local identity binding")
			}
			oidcE2EStatus(t, f.request(t, "GET", "/logout", nil, nil), http.StatusFound)
			oidcE2EStatus(t, f.request(t, "GET", "/oidc/userinfo", nil, header), http.StatusUnauthorized)
		})
	}
}

func newOIDCE2EBrowser(t *testing.T, fixture *oidcE2EFixture) *oidcE2EFixture {
	t.Helper()
	browser := *fixture
	client := *fixture.client
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser.client = &client
	return &browser
}

func assertOIDCE2ECapacityRejected(t *testing.T, response oidcE2EResponse) {
	t.Helper()
	oidcE2EStatus(t, response, http.StatusFound)
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("error") != "temporarily_unavailable" || location.Query().Get("code") != "" {
		t.Fatal("parsed capacity did not reject excess authorization")
	}
}

func TestE2EOIDCProviderDirectiveCapacity(t *testing.T) {
	t.Run("pending requests", func(t *testing.T) {
		f := newOIDCE2EFixtureWithProviderDirectives(t, "/auth", false, oidcProviderE2EDirectives("max pending requests 1"))
		other := newOIDCE2EBrowser(t, f)
		target := "/oidc/authorize?" + f.authorization("second").Encode()
		oidcE2EStatus(t, f.request(t, "GET", target, nil, nil), http.StatusSeeOther)
		assertOIDCE2ECapacityRejected(t, other.request(t, "GET", target, nil, nil))
		// Rejection must preserve the first browser's pending authorization.
		f.loginBrowser(t)
		code := oidcProviderE2ECode(t, f.request(t, "GET", "/oidc/continue", nil, nil))
		f.verifyIDToken(t, oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier)), "second")
		oidcE2EStatus(t, other.request(t, "GET", target, nil, nil), http.StatusSeeOther)
	})
	t.Run("grants", func(t *testing.T) {
		f := newOIDCE2EFixtureWithProviderDirectives(t, "/auth", false, oidcProviderE2EDirectives("max grants 1"))
		f.loginBrowser(t)
		target := "/oidc/authorize?" + f.authorization("second").Encode()
		code := oidcProviderE2ECode(t, f.request(t, "GET", target, nil, nil))
		assertOIDCE2ECapacityRejected(t, f.request(t, "GET", target, nil, nil))
		// Exhaustion must not evict an issued code or its replay tombstone.
		f.verifyIDToken(t, oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier)), "second")
		assertOIDCE2ECapacityRejected(t, f.request(t, "GET", target, nil, nil))
	})
	t.Run("sessions", func(t *testing.T) {
		f := newOIDCE2EFixtureWithProviderDirectives(t, "/auth", false, oidcProviderE2EDirectives("max sessions 1"))
		f.loginBrowser(t)
		other := newOIDCE2EBrowser(t, f)
		origin := http.Header{"Origin": {f.server.URL}}
		start := other.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
		oidcE2EStatus(t, start, http.StatusSeeOther)
		sandbox := start.header.Get("Location")
		oidcE2EStatus(t, other.request(t, "POST", sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
		oidcE2EStatus(t, other.request(t, "GET", sandbox, nil, nil), http.StatusUnauthorized)
		target := "/oidc/authorize?" + f.authorization("second").Encode()
		code := oidcProviderE2ECode(t, f.request(t, "GET", target, nil, nil))
		f.verifyIDToken(t, oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier)), "second")
		oidcE2EStatus(t, f.request(t, "GET", "/logout", nil, nil), http.StatusFound)
		other.loginBrowser(t)
		code = oidcProviderE2ECode(t, other.request(t, "GET", target, nil, nil))
		other.verifyIDToken(t, oidcE2ETokens(t, other.exchange(t, "second", code, oidcE2EVerifier)), "second")
	})
}

func TestE2EOIDCProviderDirectiveDisabled(t *testing.T) {
	f := newOIDCE2EFixtureWithProviderDirectives(t, "/auth", false, []string{"disabled"})
	completed := f.loginBrowser(t)
	for _, c := range (&http.Response{Header: completed.header}).Cookies() {
		if c.Name == "AUTHP_OIDC_SESSION_ID" && c.MaxAge > 0 {
			t.Fatal("disabled provider issued an OIDC session")
		}
	}
	for _, endpoint := range []string{"/.well-known/openid-configuration", "/oidc/jwks", "/oidc/authorize"} {
		response := f.request(t, "GET", endpoint, nil, nil)
		oidcE2EStatus(t, response, http.StatusNotFound)
	}
}
