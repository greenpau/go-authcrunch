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
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/registry"
)

// Native browser forms use the existing public UI language setting, actual
// local accounts, TLS, MFA, cross-device binding and an independent relying party.
func TestE2EI18NBrowser(t *testing.T) {
	for _, lang := range []string{"fr", "ar", "he", "ja"} {
		t.Run(lang, func(t *testing.T) {
			received := make(chan url.Values, 4)
			exchanges := make(chan oidcE2EResponse, 1)
			var f *oidcE2EFixture
			rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/callback" {
					http.NotFound(w, r)
					return
				}
				if err := r.ParseForm(); err != nil {
					w.WriteHeader(400)
					return
				}
				received <- r.Form
				// Redeem while the OP session is active. Later browser logout revokes it.
				if code := r.Form.Get("code"); code != "" {
					exchanges <- f.exchange(t, "basic", code, oidcE2EVerifier)
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(`<!doctype html><title>Callback</title><h1 id="callback">Application</h1>`))
			}))
			defer rp.Close()
			dir := t.TempDir()
			f = newOIDCE2EFixtureWithConfig(t, "/tenant/auth", true, nil, func(_ string, apps map[string]*oidc.ClientConfig) {
				client := apps["consenting-web"]
				client.ClientName = "Example Workspace"
				client.RedirectURIs = []string{rp.URL + "/callback"}
				client.Scopes = []string{"openid", "profile", "email", "address", "phone", "offline_access"}
			}, func(c *authn.PortalConfig) {
				crossDeviceConfig(t, c)
				c.UI = &ui.Parameters{Language: lang, MetaTitle: "AuthCrunch"}
				c.UserRegistries = []string{"i18n-signup"}
				c.UserTransformerConfigs = []*transformer.Config{{Matchers: []string{"exact match sub admin"}, Actions: []string{"require mfa"}}}
			}, func(c *authcrunch.Config) {
				c.Messaging = &messaging.Config{FileProviders: []*messaging.FileProvider{{Name: "i18n-mail", RootDir: filepath.Join(dir, "mail"), SenderEmail: "registration@example.test"}}}
				c.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "i18n-signup", Dropbox: filepath.Join(dir, "registrations.json"), EmailProviderName: "i18n-mail", AdminEmails: []string{"admin@example.test"}, IdentityStoreName: "oidc-local", RealmName: "local", Code: "invitation", RequireAcceptTerms: true}}}
			})
			f.callback = rp.URL + "/callback"
			params := f.authorization("basic")
			params.Set("prompt", "consent")
			params.Set("scope", "openid profile email address phone")
			params.Set("claims", `{"id_token":{"given_name":null,"acr":null},"userinfo":{"auth_time":null}}`)
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
			defer cancel()
			profile := t.TempDir()
			sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
			rpSum := sha256.Sum256(rp.Certificate().RawSubjectPublicKeyInfo)
			chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
				"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
				"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:])+","+base64.StdEncoding.EncodeToString(rpSum[:]),
				"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
				"--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
			endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			screenshots := os.Getenv("AUTHCRUNCH_I18N_SCREENSHOT_DIR")
			if screenshots == "" {
				screenshots = t.TempDir()
			}
			screenshots, err = filepath.Abs(filepath.Join(screenshots, lang))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(screenshots, 0700); err != nil {
				t.Fatal(err)
			}
			config, err := json.Marshal(map[string]string{"issuer": f.issuer, "authorize": f.issuer + "/oidc/authorize?" + params.Encode(), "lang": lang, "screenshots": screenshots, "mail": filepath.Join(dir, "mail")})
			if err != nil {
				t.Fatal(err)
			}
			driver := exec.CommandContext(ctx, "node", "ui/testdata/i18n_browser_e2e.cjs", endpoint, string(config))
			driver.Stdin = strings.NewReader(tests.TestPwd1)
			output, err := driver.CombinedOutput()
			if err != nil {
				t.Fatalf("localized browser journey failed: %v\n%s", err, output)
			}
			var result struct {
				Passed bool `json:"passed"`
			}
			if json.Unmarshal(output, &result) != nil || !result.Passed {
				t.Fatal("browser did not confirm localization")
			}
			// Native denial and form-post approval retain protocol values in every language.
			for i := range 2 {
				select {
				case response := <-received:
					if response.Get("state") != params.Get("state") || response.Get("iss") != f.issuer {
						t.Fatal("callback binding changed")
					}
					if i == 0 {
						if response.Get("error") != "access_denied" || response.Get("code") != "" {
							t.Fatal("deny decision was translated or granted access")
						}
						continue
					}
					var exchange oidcE2EResponse
					select {
					case exchange = <-exchanges:
					default:
						t.Fatal("missing code redemption")
					}
					tokens := oidcE2ETokens(t, exchange)
					f.verifyIDToken(t, tokens, "basic")
				default:
					t.Fatal("missing native OIDC callback")
				}
			}
		})
	}
}
