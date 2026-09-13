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
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func oidcTestConfig() *OIDCProviderConfig {
	return &OIDCProviderConfig{Enabled: true, Issuer: "https://auth.example.test/auth", Realms: []string{"local"}, SigningKeyFiles: []string{"../../testdata/rskeys/test_2_pri.pem"}, Clients: []*OIDCClientConfig{{ClientID: "client", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.example.test/callback"}}}}
}
func newOIDCUnitPortal(t *testing.T) *refreshPortalFixture {
	t.Helper()
	f := newRefreshPortal(t, false, false)
	c := oidcTestConfig()
	c.Clients[0].SkipConsent = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	f.portal.config.OIDCProvider = c
	if err := f.portal.configureOIDC(); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestOIDCCookieConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, mount, sessionName, requestName, wantError string
		refresh                                          bool
	}{
		{name: "custom names", mount: "/auth", sessionName: "PORTAL_LOGIN", requestName: "PORTAL_REQUEST"},
		{name: "invalid session name", mount: "/auth", sessionName: "invalid name", wantError: "invalid cookie name"},
		{name: "invalid request name", mount: "/auth", requestName: "invalid;name", wantError: "invalid cookie name"},
		{name: "optional host prefix at root", sessionName: "__Host-session", requestName: "__Host-request"},
		{name: "host session at nested mount", mount: "/auth", sessionName: "__Host-session", wantError: "root issuer path"},
		{name: "host request at nested mount", mount: "/auth", requestName: "__Host-request", wantError: "root issuer path"},
		{name: "refresh session collision", mount: "/auth", sessionName: "refresh", refresh: true, wantError: "duplicate cookie name"},
		{name: "refresh request collision", mount: "/auth", requestName: "refresh", refresh: true, wantError: "duplicate cookie name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshPortal(t, tc.refresh, false)
			c := &cookie.Config{OIDCSessionIDCookieName: tc.sessionName, OIDCRequestIDCookieName: tc.requestName}
			if tc.refresh {
				if tc.sessionName == "refresh" {
					c.OIDCSessionIDCookieName = f.portal.cookie.RefreshTokenCookieName
				} else {
					c.OIDCRequestIDCookieName = f.portal.cookie.RefreshTokenCookieName
				}
			}
			var err error
			f.portal.cookie, err = cookie.NewFactory(c)
			if err != nil {
				if tc.wantError == "" || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatal(err)
				}
				return
			}
			config := oidcTestConfig()
			config.Issuer = refreshTestOrigin + tc.mount
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			f.portal.config.OIDCProvider = config
			err = f.portal.configureOIDC()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("configuration error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			login := f.login(t, "cookie")
			_ = responseCookie(t, login, c.OIDCSessionIDCookieName)
		})
	}
}

func TestOIDCExactIssuerRouting(t *testing.T) {
	f := newOIDCUnitPortal(t)
	for _, prefix := range []string{"", "/other", "/authentication", "/auth"} {
		for _, endpoint := range []string{"/.well-known/openid-configuration", "/oidc/jwks", "/oidc/authorize", "/oidc/continue", "/oidc/token", "/oidc/userinfo", "/oidc/revoke"} {
			t.Run(prefix+endpoint, func(t *testing.T) {
				r := httptest.NewRequest("GET", refreshTestOrigin+prefix+endpoint, nil)
				w := httptest.NewRecorder()
				if handled := f.portal.oidc.HandleHTTP(w, r); handled != (prefix == "/auth") {
					t.Fatalf("OIDC route handled = %v outside expected issuer mount", handled)
				}
			})
		}
	}
}

func TestOIDCLogoutTransport(t *testing.T) {
	for _, transport := range []string{"body", "cookie"} {
		t.Run(transport, func(t *testing.T) {
			f := newRefreshPortal(t, true, false)
			config := oidcTestConfig()
			config.Clients[0].SkipConsent = true
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			f.portal.config.OIDCProvider = config
			if err := f.portal.configureOIDC(); err != nil {
				t.Fatal(err)
			}
			login := f.login(t, transport)
			if transport == "body" {
				tokens := decodeAuth(t, login)
				body, _ := json.Marshal(map[string]string{"refresh_token": tokens.RefreshToken})
				logout := f.request(t, "POST", "/auth/api/logout", string(body), false)
				if logout.Code != 200 || len(logout.Header().Values("Set-Cookie")) != 0 {
					t.Fatal("native logout failed or modified browser cookies")
				}
				invalid := f.request(t, "POST", "/auth/api/logout", `{"refresh_token":"invalid"}`, false)
				if invalid.Code != 401 || len(invalid.Header().Values("Set-Cookie")) != 0 {
					t.Fatal("invalid native logout modified browser cookies")
				}
				return
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("GET", refreshTestOrigin+"/auth/logout", nil)
			jar.SetCookies(request.URL, login.Result().Cookies())
			cookies := jar.Cookies(request.URL)
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
			confirmation := httptest.NewRecorder()
			if err := f.portal.ServeHTTP(t.Context(), confirmation, request, requests.NewRequest()); err != nil {
				t.Fatal(err)
			}
			if confirmation.Code != 200 {
				t.Fatalf("logout confirmation status=%d", confirmation.Code)
			}
			session := responseCookie(t, login, f.portal.cookie.OIDCSessionIDCookieName)
			_ = oidcUnitCode(t, oidcUnitAuthorize(t, f, session))
			logout := f.request(t, "POST", "/auth/api/logout", "{}", true, cookies...)
			if logout.Code != 200 {
				t.Fatal("browser logout failed")
			}
			params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}}
			response := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, session)
			target, _ := url.Parse(response.Header().Get("Location"))
			if target.Query().Get("error") != "login_required" {
				t.Fatal("browser logout retained provider session")
			}
		})
	}
}

func oidcUnitRequest(t *testing.T, f *refreshPortalFixture, method, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, refreshTestOrigin+"/auth"+path, strings.NewReader(form.Encode()))
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	if err := f.portal.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	return w
}

func oidcUnitAuthorize(t *testing.T, f *refreshPortalFixture, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}}.Encode(), nil, cookie)
}

func oidcUnitCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 || u.Query().Get("code") == "" {
		t.Fatal("code not issued")
	}
	return u.Query().Get("code")
}

func TestOIDCConfigurationTrustBoundaries(t *testing.T) {
	for _, name := range []string{"unknown realm", "shared key", "duplicate key", "refresh mount", "reserved mount"} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshPortal(t, name == "refresh mount", false)
			c := oidcTestConfig()
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			f.portal.config.OIDCProvider = c
			switch name {
			case "reserved mount":
				c.Issuer += "/api/tenant"
			case "unknown realm":
				c.Realms = []string{"unknown"}
			case "duplicate key":
				c.SigningKeyFiles = append(c.SigningKeyFiles, c.SigningKeyFiles[0])
			case "refresh mount":
				c.Issuer += "/another"
			case "shared key":
				config, err := kms.NewCryptoKeyStoreConfig([]string{"crypto key portal-key sign-verify from file ../../testdata/rskeys/test_2_pri.pem"})
				if err != nil {
					t.Fatal(err)
				}
				f.portal.config.CryptoKeyStoreConfig = config
				if err := f.portal.configureCryptoKeyStore(); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.portal.configureOIDC(); err == nil {
				t.Fatal("unsafe provider configuration accepted")
			}
		})
	}
}
