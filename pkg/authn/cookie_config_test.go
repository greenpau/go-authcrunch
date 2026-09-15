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
	"reflect"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
)

func TestPortalConfigureCookies(t *testing.T) {
	input, err := cookieparser.NewCookieConfigFromDirectives([]string{"cookie prefix TENANT", "cookie oidc request id name REQUEST", "cookie domain example.test path /auth"})
	if err != nil {
		t.Fatal(err)
	}
	api := &authn.APIConfig{ProfileEnabled: true}
	refresh := &authn.TokenRefreshConfig{Enabled: true}
	portal := &authn.PortalConfig{Name: "portal", API: api, RefreshTokens: refresh}
	before := input.Clone()
	if err := portal.ConfigureCookies(input); err != nil {
		t.Fatal(err)
	}
	if portal.API != api || portal.RefreshTokens != refresh || portal.CookieConfig == input || !reflect.DeepEqual(input, before) {
		t.Fatal("applying cookies changed unrelated state or input")
	}
	input.OIDCRequestIDCookieName = "changed"
	input.Domains["example.test"].Path = "/changed"
	if portal.CookieConfig.OIDCRequestIDCookieName != "REQUEST" || portal.CookieConfig.Domains["example.test"].Path != "/auth" {
		t.Fatal("portal retained caller-owned cookie settings")
	}
	previous := portal.CookieConfig
	for _, invalid := range []*cookie.Config{nil, {AccessTokenCookieName: "__Host-ACCESS", Path: "/auth"}, {SessionIDCookieName: "__Secure-SESSION", Insecure: true}, {OIDCSessionIDCookieName: "invalid name"}, {Domains: map[string]*cookie.DomainConfig{"example.test": nil}}} {
		if portal.ConfigureCookies(invalid) == nil || portal.CookieConfig != previous {
			t.Fatal("failed application changed the portal")
		}
	}
	var missing *authn.PortalConfig
	if missing.ConfigureCookies(cookie.NewConfig()) == nil {
		t.Fatal("nil portal accepted configuration")
	}
}
