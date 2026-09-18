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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

type externalLoginTestProvider struct {
	redirectURL string
}

func (p *externalLoginTestProvider) GetRealm() string          { return "upstream" }
func (p *externalLoginTestProvider) GetName() string           { return "upstream" }
func (p *externalLoginTestProvider) GetKind() string           { return "oauth" }
func (p *externalLoginTestProvider) GetDriver() string         { return "generic" }
func (p *externalLoginTestProvider) GetConfig() map[string]any { return nil }
func (p *externalLoginTestProvider) Configure() error          { return nil }
func (p *externalLoginTestProvider) Configured() bool          { return true }
func (p *externalLoginTestProvider) GetLoginIcon() *icons.LoginIcon {
	return icons.NewLoginIcon("generic")
}
func (p *externalLoginTestProvider) GetLogoutURL() string               { return "" }
func (p *externalLoginTestProvider) GetIdentityTokenCookieName() string { return "" }
func (p *externalLoginTestProvider) Request(op operator.Type, r *requests.Request) error {
	if op == operator.Authenticate {
		r.Response.Code = http.StatusFound
		if p.redirectURL != "" {
			r.Response.RedirectURL = p.redirectURL
		}
	}
	return nil
}

func TestExternalLoginSeparatesReturnURLFromProviderRedirect(t *testing.T) {
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.test", "exact", "/after-login")
	if err != nil {
		t.Fatal(err)
	}
	returnURL := "https://app.example.test/after-login"
	providerURL := "https://identity.example.test/authorize?client_id=test"

	for _, tc := range []struct {
		name             string
		path             string
		providerURL      string
		returnURL        string
		wantStatus       int
		wantLocation     string
		wantReturnCookie bool
		staleRedirectURL string
	}{
		{
			name:             "trusted return URL does not replace provider destination",
			path:             "/oauth2/upstream",
			providerURL:      providerURL,
			returnURL:        returnURL,
			wantStatus:       http.StatusFound,
			wantLocation:     providerURL,
			wantReturnCookie: true,
		},
		{
			name:             "trusted return URL does not replace SAML provider destination",
			path:             "/saml/upstream",
			providerURL:      "https://identity.example.test/saml/sso",
			returnURL:        returnURL,
			wantStatus:       http.StatusFound,
			wantLocation:     "https://identity.example.test/saml/sso",
			wantReturnCookie: true,
		},
		{
			name:         "untrusted return URL does not replace provider destination",
			path:         "/oauth2/upstream",
			providerURL:  providerURL,
			returnURL:    "https://evil.example.test/after-login",
			wantStatus:   http.StatusFound,
			wantLocation: providerURL,
		},
		{
			name:             "missing OAuth provider destination fails closed",
			path:             "/oauth2/upstream",
			returnURL:        returnURL,
			wantStatus:       http.StatusBadGateway,
			wantReturnCookie: true,
			staleRedirectURL: "https://stale.example.test/authorize",
		},
		{
			name:             "missing SAML provider destination fails closed",
			path:             "/saml/upstream",
			returnURL:        returnURL,
			wantStatus:       http.StatusBadGateway,
			wantReturnCookie: true,
			staleRedirectURL: "https://stale.example.test/saml/sso",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &externalLoginTestProvider{redirectURL: tc.providerURL}
			cookieConfig := cookie.NewConfig()
			cookieConfig.RefererCookieName = "EXTERNAL_LOGIN_RETURN"
			portal, err := NewPortal(PortalParameters{
				Config: &PortalConfig{
					Name:                           "external-login-redirect-test",
					IdentityProviders:              []string{"upstream"},
					TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted},
					CookieConfig:                   cookieConfig,
				},
				Logger:            zap.NewNop(),
				IdentityProviders: []idp.IdentityProvider{provider},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(portal.Close)

			target := "https://auth.example.test" + tc.path + "?redirect_url=" + url.QueryEscape(tc.returnURL)
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rw := httptest.NewRecorder()
			rr := requests.NewRequest()
			rr.Response.RedirectURL = tc.staleRedirectURL
			if err := portal.ServeHTTP(req.Context(), rw, req, rr); err != nil {
				t.Fatal(err)
			}
			resp := rw.Result()
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d; Location = %q", resp.StatusCode, tc.wantStatus, resp.Header.Get("Location"))
			}
			if got := resp.Header.Get("Location"); got != tc.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tc.wantLocation)
			}
			var gotReturnCookie bool
			for _, responseCookie := range resp.Cookies() {
				if responseCookie.Name == "EXTERNAL_LOGIN_RETURN" {
					gotReturnCookie = true
					if responseCookie.Value != tc.returnURL || responseCookie.Path != "/" {
						t.Fatalf("return cookie = %#v, want value %q and path /", responseCookie, tc.returnURL)
					}
				}
			}
			if gotReturnCookie != tc.wantReturnCookie {
				t.Fatalf("return cookie present = %t, want %t", gotReturnCookie, tc.wantReturnCookie)
			}
		})
	}
}
