// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

type mockIdentityProvider struct {
	realm                   string
	name                    string
	kind                    string
	driver                  string
	config                  map[string]interface{}
	logoutURL               string
	identityTokenCookieName string
}

func (m *mockIdentityProvider) GetRealm() string                       { return m.realm }
func (m *mockIdentityProvider) GetName() string                        { return m.name }
func (m *mockIdentityProvider) GetKind() string                        { return m.kind }
func (m *mockIdentityProvider) GetDriver() string                      { return m.driver }
func (m *mockIdentityProvider) GetConfig() map[string]interface{}      { return m.config }
func (m *mockIdentityProvider) Configure() error                       { return nil }
func (m *mockIdentityProvider) Configured() bool                       { return true }
func (m *mockIdentityProvider) Request(_ operator.Type, _ *requests.Request) error { return nil }
func (m *mockIdentityProvider) GetLoginIcon() *icons.LoginIcon         { return icons.NewLoginIcon("generic") }
func (m *mockIdentityProvider) GetLogoutURL() string                   { return m.logoutURL }
func (m *mockIdentityProvider) GetIdentityTokenCookieName() string     { return m.identityTokenCookieName }

func TestHandleHTTPExternalLogout(t *testing.T) {
	trustedConfig, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.com", "exact", "/bye")
	if err != nil {
		t.Fatalf("failed to build redirect config: %v", err)
	}
	if err := trustedConfig.Validate(); err != nil {
		t.Fatalf("failed to validate redirect config: %v", err)
	}

	var testcases = []struct {
		name           string
		redirectURI    string
		trustedConfigs []*redirects.RedirectURIMatchConfig
		wantLocation   string
	}{
		{
			name:           "external logout redirects when trusted",
			redirectURI:    "https://app.example.com/bye",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			wantLocation:   "https://app.example.com/bye",
		},
		{
			name:           "external logout rejects untrusted redirect_uri",
			redirectURI:    "https://evil.example.com/steal",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			wantLocation:   "/login",
		},
		{
			name:           "external logout without redirect_uri falls to login",
			redirectURI:    "",
			trustedConfigs: nil,
			wantLocation:   "/login",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := cookie.NewFactory(nil)
			v := validator.NewTokenValidator()
			provider := &mockIdentityProvider{
				realm:                   "generic",
				name:                    "generic",
				kind:                    "oauth",
				driver:                  "generic",
				config:                  map[string]interface{}{"logout_enabled": false},
				identityTokenCookieName: "generic_id_token",
			}
			p := &Portal{
				config: &PortalConfig{
					Name:                            "testPortal",
					TrustedLogoutRedirectURIConfigs: tc.trustedConfigs,
				},
				logger:            zap.L(),
				cookie:            f,
				validator:         v,
				identityProviders: []idp.IdentityProvider{provider},
			}

			rw := buildCustomResponseWriter()
			rawQuery := ""
			if tc.redirectURI != "" {
				rawQuery = "redirect_uri=" + url.QueryEscape(tc.redirectURI)
			}
			reqURL := &url.URL{
				Scheme:   "https",
				Host:     "auth.example.com",
				Path:     "/oauth2/generic/logout",
				RawQuery: rawQuery,
			}
			r := &http.Request{
				URL:    reqURL,
				Method: "GET",
				Host:   "auth.example.com",
			}
			rr := requests.NewRequest()

			err := p.handleHTTPExternalLogout(context.Background(), rw, r, rr, "oauth2")
			tests.EvalObjectsWithLog(t, "error", nil, err, []string{})
			tests.EvalObjectsWithLog(t, "status_code", http.StatusFound, rw.statusCode, []string{})

			location := rw.Header().Get("Location")
			tests.EvalObjectsWithLog(t, "location", true, strings.HasSuffix(location, tc.wantLocation), []string{})

			setCookies := rw.Header().Values("Set-Cookie")
			var hasAccessToken, hasReferer, hasSessionID bool
			for _, c := range setCookies {
				if strings.HasPrefix(c, "access_token=delete") {
					hasAccessToken = true
				}
				if strings.HasPrefix(c, "AUTHP_REDIRECT_URL=delete") {
					hasReferer = true
				}
				if strings.HasPrefix(c, "AUTHP_SESSION_ID=delete") {
					hasSessionID = true
				}
			}
			tests.EvalObjectsWithLog(t, "access_token cookie deleted", true, hasAccessToken, []string{})
			tests.EvalObjectsWithLog(t, "referer cookie deleted", true, hasReferer, []string{})
			tests.EvalObjectsWithLog(t, "session_id cookie deleted", true, hasSessionID, []string{})
		})
	}
}
