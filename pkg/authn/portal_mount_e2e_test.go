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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

func newPortalMountE2EFixture(t *testing.T, mount string) *oidcE2EFixture {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	issuer := origin + strings.TrimSuffix(mount, "/")
	database := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(database)
	if err != nil {
		t.Fatal(err)
	}
	if db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}) != nil {
		t.Fatal("seed explicit mount identity")
	}
	refresh, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"realms local", cfgutil.EncodeArgs([]string{"public", "origin", origin}), cfgutil.EncodeArgs([]string{"base", "path", mount}), "body transport enabled"})
	if err != nil {
		t.Fatal(err)
	}
	portalConfig := &authn.PortalConfig{Name: "mounted", IdentityStores: []string{"accounts"}, RefreshTokens: refresh}
	config := &authcrunch.Config{IdentityStores: []*ids.IdentityStoreConfig{{Name: "accounts", Kind: "local", Params: map[string]any{"path": database, "realm": "local"}}}, AuthenticationPortals: []*authn.PortalConfig{portalConfig}}
	application, err := oidc.NewOAuthApplicationConfig("trusted-web", &oidc.ClientConfig{ClientID: "second", ClientSecret: oidcE2ESecret, RedirectURIs: []string{"https://rp.example.test/callback?registered=yes"}, SkipConsent: true})
	if err != nil {
		t.Fatal(err)
	}
	if config.AddOAuthApplication(application) != nil {
		t.Fatal("configure explicit mount RP")
	}
	if err := config.ConfigureOIDCProvider(portalConfig, []string{cfgutil.EncodeArgs([]string{"issuer", issuer}), "realms local", "signing key files ../../testdata/rskeys/test_2_pri.pem", "applications trusted-web"}); err != nil {
		t.Fatal(err)
	}
	runtime, err := authcrunch.NewServer(config, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	portal, err := runtime.GetPortalByName("mounted")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTPAt(r.Context(), w, r, requests.NewRequest(), mount); err != nil {
			t.Error("explicit mount request failed")
		}
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &oidcE2EFixture{server: server, client: client, issuer: issuer, callback: "https://rp.example.test/callback?registered=yes"}
	f.close = func() {
		client.CloseIdleConnections()
		server.Close()
		if runtime.Close() != nil {
			t.Error("explicit mount root cleanup failed")
		}
	}
	t.Cleanup(f.close)
	return f
}

func TestE2EPortalExplicitMount(t *testing.T) {
	for _, mount := range []string{"/", "/company/auth", "/saml-service"} {
		t.Run(mount, func(t *testing.T) {
			f := newPortalMountE2EFixture(t, mount)
			// The fixture uses the public root, real TLS, runtime provider and actual
			// password checkpoints; no private portal state is exposed to the client.
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.issuer+"/.well-known/jwks.json", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.client.Do(request)
			if err != nil {
				t.Fatal("trusted discovery request failed")
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.StatusCode != 200 {
				t.Fatal("explicit mount did not serve discovery over verified TLS")
			}
			bare := f.request(t, http.MethodGet, f.server.URL+mount+"?redirect_url=", nil, nil)
			oidcE2EStatus(t, bare, 302)
			next, err := url.Parse(bare.header.Get("Location"))
			if err != nil || next.String() != f.issuer+"/login?redirect_url=" {
				t.Fatal("bare explicit mount lost mounted bound-empty login redirect")
			}
			if mount != "/" {
				trailing := f.request(t, http.MethodGet, f.issuer+"/?redirect_url=", nil, nil)
				oidcE2EStatus(t, trailing, 302)
				if trailing.header.Get("Location") != next.String() {
					t.Fatal("bare and trailing mount disagree")
				}
			}
			asset := f.request(t, http.MethodGet, "/assets/js/login.js", nil, nil)
			oidcE2EStatus(t, asset, 200)
			if !strings.Contains(asset.header.Get("Content-Type"), "javascript") {
				t.Fatal("mounted asset selected wrong owner")
			}
			keys := f.request(t, http.MethodGet, "/.well-known/jwks.json", nil, nil)
			oidcE2EStatus(t, keys, 200)
			head := f.request(t, http.MethodHead, "/.well-known/jwks.json", nil, nil)
			oidcE2EStatus(t, head, 200)
			if len(head.body) != 0 || keys.header.Get("Content-Type") != "application/jwk-set+json" || head.header.Get("Content-Length") != keys.header.Get("Content-Length") || len(keys.header.Values("Set-Cookie")) != 0 || keys.header.Get("Cache-Control") != "no-store" {
				t.Fatal("explicit JWKS changed public discovery contract")
			}
			metadata := f.request(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
			oidcE2EStatus(t, metadata, 200)
			var discovery struct {
				Issuer string `json:"issuer"`
			}
			if json.Unmarshal(metadata.body, &discovery) != nil || discovery.Issuer != f.issuer {
				t.Fatal("explicit mount changed OP issuer")
			}
			for _, endpoint := range []string{"/api/.well-known/jwks.json", "/other/.well-known/jwks.json", "/%2ewell-known/jwks.json"} {
				impostor := f.request(t, http.MethodGet, endpoint, nil, nil)
				if impostor.header.Get("Content-Type") == "application/jwk-set+json" || strings.Contains(string(impostor.body), `"keys"`) {
					t.Fatal("nested or encoded suffix published signing discovery")
				}
			}
			if mount != "/" {
				for _, target := range []string{f.server.URL + "/outside/.well-known/jwks.json", f.issuer + "entic/.well-known/openid-configuration", f.server.URL + "/outside/oidc/jwks", f.server.URL + "/" + strings.Replace(strings.TrimPrefix(mount, "/"), "/", "%2F", 1) + "%2Flogin"} {
					denied := f.request(t, http.MethodGet, target, nil, nil)
					oidcE2EStatus(t, denied, 404)
					if len(denied.header.Values("Set-Cookie")) != 0 || denied.header.Get("Cache-Control") != "no-store" {
						t.Fatal("outside boundary changed browser state")
					}
				}
			}
			checkAPI := func() {
				t.Helper()
				for _, endpoint := range []string{"/api/logout", "/api/refresh_token", "/api/refresh_session"} {
					r := f.request(t, http.MethodGet, endpoint, nil, http.Header{"Accept": {"text/html"}})
					oidcE2EStatus(t, r, 405)
					if r.header.Get("Allow") != "POST" || r.header.Get("Location") != "" || len(r.header.Values("Set-Cookie")) != 0 || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
						t.Fatal("API ownership changed on HTML GET")
					}
				}
			}
			checkAPI()
			completed := f.loginBrowser(t)
			found := false
			for _, c := range (&http.Response{Header: completed.header}).Cookies() {
				if c.Name == "AUTHP_REFRESH_TOKEN" && c.MaxAge > 0 {
					found = true
					if c.Path != mount {
						t.Fatal("refresh cookie escaped declared mount")
					}
				}
			}
			if !found {
				t.Fatal("explicit password login did not deliver refresh credential")
			}
			identity := func() string {
				t.Helper()
				r := f.request(t, http.MethodGet, "/whoami?format=json", nil, nil)
				oidcE2EStatus(t, r, 200)
				var claims struct{ Sub, Email, SID string }
				if json.Unmarshal(r.body, &claims) != nil || claims.Sub != "alice" || claims.Email != "alice@example.test" || claims.SID == "" {
					t.Fatal("mounted identity probe lost local identity/session")
				}
				return claims.SID
			}
			before := identity()
			checkAPI()
			if identity() != before {
				t.Fatal("API method denial changed current session")
			}
			code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
			tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
			f.verifyIDToken(t, tokens, "second")
		})
	}
}
