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

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Several tabs of one browser wait on the login page, each sent there by its
// own page. The user signs in from one of them; every other tab must then leave
// for its own destination without a second login and without a reload.
func TestE2ELoginElsewhereSendsWaitingTabsHomeBrowser(t *testing.T) {
	for _, theme := range []string{"basic", "legacy"} {
		t.Run(theme, func(t *testing.T) { testLoginElsewhereBrowser(t, theme) })
	}
}

func testLoginElsewhereBrowser(t *testing.T, theme string) {
	t.Helper()
	received := make(chan url.Values, 5)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/receive" {
			http.NotFound(w, r)
			return
		}
		select {
		case received <- r.URL.Query():
		default:
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>External form receiver</title>"))
	}))
	t.Cleanup(receiver.Close)
	uiConfig := &ui.Parameters{}
	if theme == "legacy" {
		legacy, err := os.ReadFile("ui/testdata/login_legacy.template")
		if err != nil {
			t.Fatal(err)
		}
		// A theme may offer ordinary GET navigation in addition to its password
		// POST form. Browsers replace the GET action's query with form controls.
		source := strings.Replace(string(legacy), "<head>", `<head><base href="/">`, 1)
		// Browsers retain the first duplicate attribute, including script src.
		source = strings.Replace(source, `/assets/js/login.js" }}">`, `/assets/js/login.js" }}" src="https://unused.example.test/custom.js">`, 1)
		source = strings.Replace(source, "</body>", `<input form="legacy-get" name="note" dirname="redirect_url" value="ordinary"><textarea form="legacy-get" name="message" dirname="fresh">ordinary</textarea><select form="legacy-get" name="redirect_url"><option>https://wrong.example.test/select</option></select><input name="redirect_url" form="legacy-get" value="https://wrong.example.test/preceding"><input name="fresh" form="legacy-get" value="0"><form id="legacy-get" action="login"><input name="redirect_url" value="https://wrong.example.test/"><button>Continue</button></form>
<form id="legacy-empty" action=""><button id="legacy-empty-submit">Continue</button></form>
<form id="legacy-method" action="login" method="post"><input name="redirect_url" value="https://wrong.example.test/"><button id="legacy-method-submit" formmethod="get">Continue</button></form>
<form id="legacy-unicode-method" action="login" method="post"><input name="redirect_url" value="https://wrong.example.test/"><button id="legacy-unicode-method-submit" formmethod="poſt">Continue</button></form>
<form id="legacy-unicode-reset" action="login"><input name="note" value="ordinary"><button id="legacy-unicode-reset-submit" type="reſet" formaction="`+receiver.URL+`/receive">External</button></form>
<button id="legacy-external-submit" form="legacy-external" formaction="`+receiver.URL+`/receive">External</button>
<form id="legacy-external" action="login"><input name="note" value="ordinary"></form>
<form id="legacy-nested-external" action="`+receiver.URL+`/receive"><form id="legacy-ignored" action="login"><input name="note" value="ordinary"><button id="legacy-nested-submit">External</button></form></form>
<form id="legacy-ignored" action="login"></form>
<table><b><form id="legacy-table" action="login"><tr><td><input name="note" value="ordinary"><button id="legacy-table-submit" formaction="`+receiver.URL+`/receive">External</button></td></tr></form></b></table>
<div><form id="legacy-closed" action="login"><input name="note" value="ordinary"></div><button id="legacy-closed-submit" formaction="`+receiver.URL+`/receive">External</button></form></body>`, 1)
		file := filepath.Join(t.TempDir(), "legacy.template")
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		uiConfig.Templates = map[string]string{"login": file}
	}

	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", server.Listener.Addr().String(), "prefix", "/_test/tab/")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"},
	}}); err != nil {
		t.Fatal("could not provision login-elsewhere identity")
	}
	runtime, err := authcrunch.NewServer(&authcrunch.Config{
		IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}},
		AuthenticationPortals: []*authn.PortalConfig{{
			Name: "login-elsewhere", UI: uiConfig, IdentityStores: []string{"local"},
			RawCryptoKeyStoreConfig:        []string{"crypto key rsa-current sign-verify from file ../../testdata/rskeys/test_2_pri.pem"},
			TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted},
		}},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		if err := runtime.Close(); err != nil {
			t.Errorf("close login-elsewhere runtime: %v", err)
		}
	})
	portal, err := runtime.GetPortalByName("login-elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_test/tab/") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><title>Destination</title>"))
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Errorf("login-elsewhere portal request failed: %v", err)
		}
	})
	server.StartTLS()

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	profile := t.TempDir()
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	receiverSum := sha256.Sum256(receiver.Certificate().RawSubjectPublicKeyInfo)
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:])+","+base64.StdEncoding.EncodeToString(receiverSum[:]),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad",
		"--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	params, err := json.Marshal(map[string]string{"origin": server.URL, "theme": theme, "receiver": receiver.URL})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/login_elsewhere_browser_e2e.cjs", endpoint, string(params))
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("login-elsewhere browser check failed: %v\n%s", err, output)
	}
	if theme == "legacy" {
		for range 5 {
			select {
			case values := <-received:
				if values.Has("redirect_url") || values.Has("fresh") || values.Get("note") != "ordinary" {
					t.Fatal("external form received portal navigation or lost ordinary fields")
				}
			default:
				t.Fatal("external form submission did not reach the receiver")
			}
		}
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm that waiting tabs left for their destinations")
	}
}
