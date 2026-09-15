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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Chrome enforces reserved prefixes that Go's cookie jar does not enforce.
// The old-deletion route is a negative control; login, authorization and logout
// all use production handlers and the shared public directive parser.
func TestE2ECookieBrowserLogout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		directives []string
		reserved   bool
		base       string
	}{
		{name: "defaults", base: "/auth"},
		{name: "custom prefix", directives: []string{"cookie prefix PORTAL", "cookie access token name AUTHP_LOGIN_ACCESS"}, base: "/auth"},
		{name: "secure prefix", directives: []string{"cookie prefix __Secure-PORTAL", "cookie path /auth"}, reserved: true, base: "/auth"},
		{name: "host access and session", directives: []string{"cookie access token name __Host-ACCESS", "cookie session id name __Host-SESSION"}, reserved: true, base: "/auth"},
		{name: "mixed-case host root", directives: []string{"cookie access token name __hOsT-ACCESS", "cookie session id name __hOsT-SESSION", "cookie referer name __Host-REFERER", "cookie sandbox id name __Host-SANDBOX"}, reserved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := cookieparser.NewCookieConfigFromDirectives(tc.directives)
			if err != nil {
				t.Fatal(err)
			}
			f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(config *authn.PortalConfig) {
				// Profile reads need the stored identity's email; this fixture's
				// default claim-rewriting scenario belongs to identity tests.
				config.UserTransformerConfigs = nil
			}, c)
			gate, err := authz.NewGatekeeper(&authz.PolicyConfig{
				Name: "cookie-browser", AuthURLPath: tc.base + "/login", SessionIDCookieName: c.SessionIDCookieName, AccessTokenCookieNames: []string{c.AccessTokenCookieName}, AllowedTokenSources: []string{"cookie"},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
				RawCryptoKeyStoreConfig: []string{"crypto key rsa-current verify from file ../../testdata/rskeys/test_2_pub.pem"},
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(gate.Close)
			portalHandler := f.server.Config.Handler
			// No HTTP requests have started yet. Wrap only test controls and the
			// protected resource; all portal routes keep the original handler.
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "no-store")
				switch r.URL.Path {
				case "/_test/blank":
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<!doctype html><title>Cookie regression</title>"))
				case "/_test/old-delete":
					path := c.Path
					if path == "" {
						path = "/"
					}
					http.SetCookie(w, &http.Cookie{Name: c.AccessTokenCookieName, Value: "delete", Path: path, Expires: time.Unix(0, 0)})
					http.SetCookie(w, &http.Cookie{Name: c.SessionIDCookieName, Value: "delete", Path: "/", Expires: time.Unix(0, 0)})
				case "/auth/protected", "/outside/protected":
					ar := requests.NewAuthorizationRequest()
					if err := gate.Authenticate(w, r, ar); err == nil && ar.Response.Authorized {
						w.WriteHeader(http.StatusNoContent)
					}
				default:
					portalHandler.ServeHTTP(w, r)
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			profile := t.TempDir()
			sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
			chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
				"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
				"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:]),
				"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
				"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad",
				"--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
			endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			params, err := json.Marshal(map[string]any{"origin": f.server.URL, "base": tc.base, "access": c.AccessTokenCookieName, "session": c.SessionIDCookieName, "sandbox": c.SandboxIDCookieName, "reserved": tc.reserved, "scoped": c.Path == "/auth"})
			if err != nil {
				t.Fatal(err)
			}
			driver := exec.CommandContext(ctx, "node", "ui/testdata/cookie_browser_e2e.cjs", endpoint, string(params))
			driver.Stdin = strings.NewReader(tests.TestPwd1)
			output, err := driver.CombinedOutput()
			if err != nil {
				t.Fatalf("cookie browser regression failed: %v\n%s", err, output)
			}
			var result struct {
				Passed bool `json:"passed"`
			}
			if json.Unmarshal(output, &result) != nil || !result.Passed {
				t.Fatal("browser did not confirm cookie logout")
			}
		})
	}
}

func TestE2ECookiePortalMountValidation(t *testing.T) {
	c, err := cookieparser.NewCookieConfigFromDirectives([]string{"cookie sandbox id name __Host-SANDBOX"})
	if err != nil {
		t.Fatal(err)
	}
	f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(config *authn.PortalConfig) {
		if err := config.ConfigureCookies(c); err != nil {
			t.Fatal(err)
		}
	})
	discovery := f.request(t, http.MethodGet, e2eJWKSPath, nil, nil)
	if discovery.status != http.StatusOK || len(discovery.header.Values("Set-Cookie")) != 0 {
		t.Fatal("cookie mount validation blocked public discovery")
	}
	response := f.request(t, http.MethodGet, "/login", nil, nil)
	if response.status != http.StatusInternalServerError || len(response.header.Values("Set-Cookie")) != 0 {
		t.Fatal("incompatible portal mount emitted cookies")
	}
}
