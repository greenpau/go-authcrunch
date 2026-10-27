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

package authn_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
)

func TestE2EEmbeddedApplications(t *testing.T) {
	for _, mount := range []string{"/", "/auth", "/xauth", "/tenant/security", "/documents-team", "/tenant/a+b&c"} {
		for _, explicit := range []bool{false, true} {
			label := mount + "/inferred"
			if explicit {
				label = mount + "/explicit"
			}
			t.Run(label, func(t *testing.T) {
				f := newDocumentsE2E(t, mount, true, func(cfg *authn.PortalConfig) {
					cfg.API.AdminEnabled, cfg.API.ProfileEnabled = true, true
					cfg.UserTransformerConfigs = []*transformer.Config{{Matchers: []string{"exact match sub alice"}, Actions: []string{"add role authp/admin"}}}
				})
				if explicit {
					f.declaredMount = mount
				}
				t.Cleanup(func() { f.server.Close(); requireEmbeddedAppPortClosed(t, f.server.Listener.Addr().String()) })
				client := *f.client
				client.Jar, _ = cookiejar.New(nil)
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				issuer := f.server.URL + strings.TrimSuffix(mount, "/")
				browser := &oidcE2EFixture{server: f.server, client: &client, issuer: issuer}
				webAuthnEnrollmentLogin(t, browser, "alice", tests.TestPwd1)
				for _, app := range []string{"profile", "operator", "documents"} {
					for _, child := range []string{"/", "/preferences", "/debug", "/unknown/deep/link", "/provider/local", "/connected-accounts/", "/cross-device", "/api/server/user"} {
						response := browser.request(t, http.MethodGet, "/"+app+child+"?format=json", nil, nil)
						oidcE2EStatus(t, response, http.StatusOK)
						if !strings.Contains(html.UnescapeString(string(response.body)), `<base href="`+strings.TrimSuffix(mount, "/")+"/"+app+`/" />`) || response.header.Get("Content-Type") != "text/html" || response.header.Get("Cache-Control") != "no-store" || strings.Contains(string(response.body), "__AUTHCRUNCH_APP_BASE_PATH__") {
							t.Fatalf("wrong app entry or base: %s%s", app, child)
						}
					}
					dotted := browser.request(t, http.MethodGet, "/"+app+"/users/local/alice@example.test", nil, http.Header{"Accept": {"text/html"}})
					oidcE2EStatus(t, dotted, http.StatusOK)
					if dotted.header.Get("Content-Type") != "text/html" {
						t.Fatal("dotted client route did not load the app")
					}
					redirect := browser.request(t, http.MethodGet, "/"+app+"?q=kept", nil, nil)
					oidcE2EStatus(t, redirect, http.StatusPermanentRedirect)
					if redirect.header.Get("Location") != "/"+strings.Trim(strings.TrimSuffix(mount, "/")+"/"+app, "/")+"/?q=kept" {
						t.Fatal("bare app redirect lost its mount or query")
					}
					asset := browser.request(t, http.MethodGet, "/"+app+"/i18n/en.json", nil, nil)
					oidcE2EStatus(t, asset, http.StatusOK)
					if asset.header.Get("Content-Type") != "application/json" || asset.header.Get("Etag") == "" {
						t.Fatal("invalid app asset")
					}
					conditional := browser.request(t, http.MethodGet, "/"+app+"/i18n/en.json", nil, http.Header{"If-None-Match": {asset.header.Get("Etag")}})
					oidcE2EStatus(t, conditional, http.StatusNotModified)
					head := browser.request(t, http.MethodHead, "/"+app+"/preferences", nil, nil)
					oidcE2EStatus(t, head, http.StatusOK)
					if len(head.body) != 0 {
						t.Fatal("HEAD returned an app body")
					}
					for _, missing := range []string{"/assets/missing.js", "/assets/missing", "/i18n/missing.json", "/i18n/missing"} {
						oidcE2EStatus(t, browser.request(t, http.MethodGet, "/"+app+missing, nil, nil), http.StatusNotFound)
					}
					oidcE2EStatus(t, browser.request(t, http.MethodPost, "/"+app+"/", nil, nil), http.StatusMethodNotAllowed)
					anonymous := *f.client
					anonymous.Jar = nil
					request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, issuer+"/"+app+"/manifest.json", nil)
					response, err := anonymous.Do(request)
					if err != nil {
						t.Fatal("anonymous manifest request failed")
					}
					_, _ = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != http.StatusOK {
						t.Fatal("exact manifest is not public")
					}
					for _, child := range []string{"/", "/assets/private.js", "/nested/" + app + "/manifest.json"} {
						request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, issuer+"/"+app+child, nil)
						denied, err := anonymous.Do(request)
						if err != nil {
							t.Fatal("anonymous app request failed")
						}
						denied.Body.Close()
						if denied.StatusCode != http.StatusUnauthorized {
							t.Fatal("anonymous request bypassed app authorization")
						}
					}
				}
				portal := browser.request(t, http.MethodGet, "/portal?redirect_url=", nil, nil)
				oidcE2EStatus(t, portal, http.StatusOK)
				for _, app := range []string{"profile", "operator", "documents"} {
					if !strings.Contains(html.UnescapeString(string(portal.body)), `href="`+strings.TrimSuffix(mount, "/")+"/"+app+`/"`) {
						t.Fatal("portal omitted mounted app link")
					}
				}
				runEmbeddedApplicationsBrowser(t, browser)
				// A member can use Profile and File Vault but cannot download the admin app.
				member := *f.client
				member.Jar, _ = cookiejar.New(nil)
				member.CheckRedirect = client.CheckRedirect
				other := &oidcE2EFixture{server: f.server, client: &member, issuer: issuer}
				webAuthnEnrollmentLogin(t, other, "bob", tests.TestPwd2)
				oidcE2EStatus(t, other.request(t, http.MethodGet, "/operator/", nil, nil), http.StatusForbidden)
				oidcE2EStatus(t, other.request(t, http.MethodGet, "/profile/", nil, nil), http.StatusOK)
				oidcE2EStatus(t, other.request(t, http.MethodGet, "/documents/", nil, nil), http.StatusOK)
				landing := other.request(t, http.MethodGet, "/portal?redirect_url=", nil, nil)
				if strings.Contains(string(landing.body), "Security Manager") {
					t.Fatal("member portal advertised administration")
				}
			})
		}
	}
}

func TestE2EEmbeddedApplicationsDisabled(t *testing.T) {
	f := newDocumentsE2E(t, "/xauth", false)
	for _, app := range []string{"operator", "documents"} {
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/xauth/"+app+"/manifest.json", nil)
		response, err := f.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatal("disabled app became available")
		}
	}
}

func runEmbeddedApplicationsBrowser(t *testing.T, f *oidcE2EFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	profile := t.TempDir()
	sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t), "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile, "--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:]), "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stop()
		browserURL, err := url.Parse(endpoint)
		if err != nil {
			t.Error("invalid browser endpoint")
			return
		}
		requireEmbeddedAppPortClosed(t, browserURL.Host)
	}()
	origin, _ := url.Parse(f.issuer + "/portal")
	cookies := []map[string]any{}
	for _, cookie := range f.client.Jar.Cookies(origin) {
		cookies = append(cookies, map[string]any{"name": cookie.Name, "value": cookie.Value, "url": f.issuer + "/portal", "path": "/", "secure": true, "httpOnly": true, "sameSite": "Lax"})
	}
	data, err := json.Marshal(map[string]any{"issuer": f.issuer, "cookies": cookies})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/portal_apps_browser_e2e.cjs", endpoint)
	driver.Stdin = strings.NewReader(string(data))
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded app browser journey failed: %v: %s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm app journeys")
	}
}

func requireEmbeddedAppPortClosed(t *testing.T, address string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Error("embedded app validation left a listener open")
	}
}
