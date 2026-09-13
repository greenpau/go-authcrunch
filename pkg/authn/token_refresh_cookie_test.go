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
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/ids"
)

func TestTokenRefreshCookieConfiguration(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	for _, tc := range []struct {
		name, override, mount, want, wantError string
		cookies                                *cookie.Config
		disabled                               bool
	}{
		{name: "absent cookie config", want: "AUTHP_REFRESH_TOKEN"},
		{name: "default cookie config", cookies: cookie.NewConfig(), want: "AUTHP_REFRESH_TOKEN"},
		{name: "empty cookie config", cookies: &cookie.Config{}, want: "AUTHP_REFRESH_TOKEN"},
		{name: "custom prefix", cookies: &cookie.Config{CookieNamePrefix: "TENANT"}, want: "TENANT_REFRESH_TOKEN"},
		{name: "explicit cookie config", cookies: &cookie.Config{CookieNamePrefix: "TENANT", RefreshTokenCookieName: "LOGIN_REFRESH"}, want: "LOGIN_REFRESH"},
		{name: "directive override", override: "CUSTOM_REFRESH_TOKEN", want: "CUSTOM_REFRESH_TOKEN"},
		{name: "directive overrides prefix", cookies: &cookie.Config{CookieNamePrefix: "TENANT"}, override: "CUSTOM_REFRESH_TOKEN", want: "CUSTOM_REFRESH_TOKEN"},
		{name: "directive overrides cookie name", cookies: &cookie.Config{RefreshTokenCookieName: "COOKIE_REFRESH"}, override: "DIRECTIVE_REFRESH", want: "DIRECTIVE_REFRESH"},
		{name: "matching settings", cookies: &cookie.Config{RefreshTokenCookieName: "CUSTOM_REFRESH_TOKEN"}, override: "CUSTOM_REFRESH_TOKEN", want: "CUSTOM_REFRESH_TOKEN"},
		{name: "disabled override", disabled: true, cookies: &cookie.Config{CookieNamePrefix: "TENANT"}, override: "UNUSED_REFRESH", want: "TENANT_REFRESH_TOKEN"},
		{name: "invalid inherited name", cookies: &cookie.Config{RefreshTokenCookieName: "invalid name"}, wantError: "invalid refresh cookie name"},
		{name: "invalid override", override: "invalid;name", wantError: "invalid refresh cookie name"},
		{name: "optional host prefix at root", cookies: &cookie.Config{RefreshTokenCookieName: "__Host-CUSTOM_REFRESH_TOKEN"}, mount: "/", want: "__Host-CUSTOM_REFRESH_TOKEN"},
		{name: "optional host prefix at nested mount", cookies: &cookie.Config{RefreshTokenCookieName: "__Host-CUSTOM_REFRESH_TOKEN"}, wantError: "root path"},
		{name: "access cookie collision", override: "AUTHP_ACCESS_TOKEN", wantError: "duplicate cookie name"},
		{name: "session cookie collision", override: "AUTHP_SESSION_ID", wantError: "duplicate cookie name"},
		{name: "sandbox cookie collision", override: "AUTHP_SANDBOX_ID", wantError: "duplicate cookie name"},
		{name: "identity cookie collision", override: "AUTHP_ID_TOKEN", wantError: "duplicate cookie name"},
		{name: "referer cookie collision", override: "AUTHP_REDIRECT_URL", wantError: "duplicate cookie name"},
		{name: "OIDC session cookie collision", override: "AUTHP_OIDC_SESSION_ID", wantError: "duplicate cookie name"},
		{name: "OIDC request cookie collision", override: "AUTHP_OIDC_REQUEST_ID", wantError: "duplicate cookie name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *f.portal.config
			refresh := *cfg.RefreshTokens
			cfg.RefreshTokens, cfg.CookieConfig = &refresh, tc.cookies
			refresh.CookieName, refresh.Enabled = tc.override, !tc.disabled
			if tc.mount != "" {
				refresh.BasePath = tc.mount
			}
			p, err := NewPortal(PortalParameters{Config: &cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{f.store}})
			if p != nil {
				t.Cleanup(p.Close)
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("configuration error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.cookie.RefreshTokenCookieName != tc.want || p.config.CookieConfig.RefreshTokenCookieName != tc.want {
				t.Fatal("refresh cookie did not use the shared factory configuration")
			}
			if refresh.CookieName != tc.override {
				t.Fatal("cookie default became an explicit feature override")
			}
		})
	}
}
