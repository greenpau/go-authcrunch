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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Several tabs of one browser wait on the login page, each sent there by its
// own page. The user signs in from one of them; every other tab must then leave
// for its own destination without a second login and without a reload.
func TestE2ELoginElsewhereSendsWaitingTabsHomeBrowser(t *testing.T) {
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
			Name: "login-elsewhere", IdentityStores: []string{"local"},
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
	params, err := json.Marshal(map[string]string{"origin": server.URL})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/login_elsewhere_browser_e2e.cjs", endpoint, string(params))
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("login-elsewhere browser check failed: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm that waiting tabs left for their destinations")
	}
}
