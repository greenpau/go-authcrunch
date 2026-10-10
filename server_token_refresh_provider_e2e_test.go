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

package authcrunch_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
)

// Root composition accepts the same reusable provider/refresh parser results
// as standalone portals. The real callback/rotation matrix lives with authn;
// this journey verifies registration, serialization and mixed-source assembly.
func TestE2EServerTokenRefreshProviderComposition(t *testing.T) {
	configure := func(cfg *authcrunch.Config) {
		provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", []string{
			"realm upstream", "driver generic", "client_id portal", "client_secret synthetic-test-secret",
			"base_auth_url https://upstream.example.test", "issuer https://upstream.example.test", "authorization_url https://upstream.example.test/authorize", "token_url https://upstream.example.test/token",
			"jwks key pinned testdata/rskeys/test_2_pub.pem",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.AddIdentityProvider(provider.Name, provider.Kind, provider.Params); err != nil {
			t.Fatal(err)
		}
		portal := cfg.AuthenticationPortals[0]
		portal.IdentityProviders = []string{provider.Name}
		refresh, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"realms local upstream", "provider revalidation upstream snapshot", "public origin " + portal.RefreshTokens.PublicOrigin, "base path /tenant/auth", "body transport enabled"})
		if err != nil {
			t.Fatal(err)
		}
		portal.RefreshTokens = refresh
	}
	f := newServerCompositionFixture(t, false, configure)
	f.login(t, "local", "alice")
	compositionStatus(t, f.request(t, http.MethodPost, "/api/refresh_token", "{}", http.Header{"Origin": {f.origin}, "Content-Type": {"application/json"}, "X-Authcrunch-Refresh": {"1"}}), http.StatusOK)
	f.client.Jar, _ = cookiejar.New(nil)
	initiation := f.request(t, http.MethodGet, "/oauth2/upstream", "", nil)
	compositionStatus(t, initiation, http.StatusFound)
	location, err := url.Parse(initiation.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != "upstream.example.test" || location.Query().Get("state") == "" || location.Query().Get("nonce") == "" || location.Query().Get("code_challenge") == "" {
		t.Fatal("root dispatch did not begin a bound OAuth login")
	}
}
