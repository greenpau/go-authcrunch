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
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// Drive actual login and consent forms in Chrome. The relying party receives
// redirects/form posts over TLS; Go independently redeems and verifies each code.
func TestE2EOIDCThemedBrowser(t *testing.T) {
	for _, custom := range []bool{false, true} {
		name := "basic"
		if custom {
			name = "custom"
		}
		t.Run(name, func(t *testing.T) { runOIDCThemedBrowser(t, custom) })
	}
}

func runOIDCThemedBrowser(t *testing.T, custom bool) {
	type callback struct {
		method  string
		values  url.Values
		referer string
	}
	received := make(chan callback, 8)
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- callback{r.Method, r.Form, r.Header.Get("Referer")}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`<!doctype html><html lang="en"><title>Application callback</title><body><h1>Returned to application</h1></body></html>`))
	}))
	defer rp.Close()
	paramsUI := &ui.Parameters{MetaTitle: "AuthCrunch", LogoDescription: "AuthCrunch"}
	paramsUI.PrivateLinks = []*ui.Link{
		{Title: "My Website", Link: "/", IconName: "las la-star", IconEnabled: true},
		{Title: "My Identity", Link: "/tenant/auth/whoami", IconName: "las la-user", IconEnabled: true},
		{Title: "User Profile", Link: "/tenant/auth/profile", IconName: "las la-cog", IconEnabled: true},
	}
	primaryColor, bannerName, backgroundName := "rgb(36, 91, 202)", "banner.svg", "background.svg"
	if custom {
		// Custom assets are process-global; restore the registry after this case.
		original := ui.StaticAssets
		isolated, err := ui.NewStaticAssetLibrary()
		if err != nil {
			t.Fatal(err)
		}
		ui.StaticAssets = isolated
		t.Cleanup(func() { ui.StaticAssets = original })
		paramsUI.MetaTitle = "Example Workspace"
		paramsUI.LogoDescription = "Example Workspace"
		paramsUI.LogoURL = "/assets/images/theme-logo.svg"
		paramsUI.CustomCSSPath = filepath.Join(t.TempDir(), "theme.css")
		css := `.basic-theme { --brand-primary: #6238a8; --brand-primary-hover: #49277e; --brand-focus: #6238a8; --brand-page: #f5f0fb; --brand-page-image: url("../images/theme-background.svg"); --brand-banner-image: url("../images/theme-banner.svg"); --brand-banner-height: 40px; }`
		if err := os.WriteFile(paramsUI.CustomCSSPath, []byte(css), 0600); err != nil {
			t.Fatal(err)
		}
		for _, asset := range []string{"theme-logo.svg", "theme-banner.svg", "theme-background.svg", "favicon.svg"} {
			file := filepath.Join(t.TempDir(), asset)
			artwork := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="20" fill="#6238a8"/><path d="m25 50 15 15 35-35" fill="none" stroke="white" stroke-width="8"/></svg>`
			if asset == "theme-background.svg" {
				artwork = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1000"><path fill="#f5f0fb" d="M0 0h1600v1000H0z"/><path fill="#e4d9f6" d="M0 0h400L0 400z"/></svg>`
			}
			if err := os.WriteFile(file, []byte(artwork), 0600); err != nil {
				t.Fatal(err)
			}
			paramsUI.StaticAssets = append(paramsUI.StaticAssets, &ui.StaticAsset{Path: "assets/images/" + asset, ContentType: "image/svg+xml", FsPath: file})
		}
		primaryColor, bannerName, backgroundName = "rgb(98, 56, 168)", "theme-banner.svg", "theme-background.svg"
	}
	f := newOIDCE2EFixtureWithConfig(t, "/tenant/auth", true, nil, func(_ string, apps map[string]*oidc.ClientConfig) {
		client := apps["consenting-web"]
		client.ClientName = "Example Workspace"
		client.RedirectURIs = []string{rp.URL + "/callback"}
		client.Scopes = []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	}, func(c *authn.PortalConfig) { c.UI = paramsUI }, func(c *authcrunch.Config) {
		if custom {
			return // Retain coverage of single-realm login alongside selection.
		}
		for _, realm := range []string{"engineering", "operations", "contractors"} {
			name := "theme-" + realm
			c.IdentityStores = append(c.IdentityStores, &ids.IdentityStoreConfig{Name: name, Kind: "local", Params: map[string]any{"path": c.IdentityStores[0].Params["path"], "realm": realm}})
			c.AuthenticationPortals[0].IdentityStores = append(c.AuthenticationPortals[0].IdentityStores, name)
		}
	})
	f.callback = rp.URL + "/callback"
	origins := make(chan string, 8)
	portalHandler := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/oidc/continue") {
			origins <- "origin=" + r.Header.Get("Origin") + "; site=" + r.Header.Get("Sec-Fetch-Site")
		}
		portalHandler.ServeHTTP(w, r)
	})
	params := f.authorization("basic")
	params.Set("prompt", "consent")
	params.Set("scope", "openid")
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	profile := t.TempDir()
	sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
	rpSum := sha256.Sum256(rp.Certificate().RawSubjectPublicKeyInfo)
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:])+","+base64.StdEncoding.EncodeToString(rpSum[:]),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad",
		"--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	screenshots := os.Getenv("AUTHCRUNCH_OIDC_SCREENSHOT_DIR")
	if screenshots == "" {
		screenshots = t.TempDir()
	} else if custom {
		screenshots = filepath.Join(screenshots, "custom")
	}
	screenshots, err = filepath.Abs(screenshots)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(screenshots, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]string{"issuer": f.issuer, "authorize": f.issuer + "/oidc/authorize?" + params.Encode(), "callback": f.callback, "screenshots": screenshots, "primaryColor": primaryColor, "bannerName": bannerName, "backgroundName": backgroundName})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/oidc_browser_e2e.cjs", endpoint, string(config))
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		for len(origins) > 0 {
			t.Log(<-origins)
		}
		t.Fatalf("OIDC browser journey failed: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm the OIDC journey")
	}
	if len(origins) != 4 {
		t.Fatal("missing native consent submissions")
	}
	for len(origins) > 0 {
		if <-origins != "origin="+f.server.URL+"; site=same-origin" {
			t.Fatal("consent form did not preserve its origin")
		}
	}
	// Allow, deny, automatic form_post and no-JavaScript manual form_post.
	for i, method := range []string{"GET", "GET", "POST", "POST"} {
		select {
		case response := <-received:
			if response.referer != "" {
				t.Fatal("authorization page leaked a cross-origin referrer")
			}
			if response.method != method || response.values.Get("state") != params.Get("state") || response.values.Get("iss") != f.issuer {
				t.Fatal("callback method or response binding changed")
			}
			if i == 1 {
				if response.values.Get("error") != "access_denied" || response.values.Get("code") != "" {
					t.Fatal("browser Deny granted access")
				}
				continue
			}
			if response.values.Get("code") == "" || response.values.Get("error") != "" {
				t.Fatal("browser Allow did not grant a code")
			}
			tokens := oidcE2ETokens(t, f.exchange(t, "basic", response.values.Get("code"), oidcE2EVerifier))
			f.verifyIDToken(t, tokens, "basic")
		case <-ctx.Done():
			t.Fatal("browser did not reach the relying party")
		}
	}
}
