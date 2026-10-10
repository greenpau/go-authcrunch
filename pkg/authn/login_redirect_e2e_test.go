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
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
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

type loginRedirectFixture struct {
	server *httptest.Server
	client *http.Client
}

func newLoginRedirectFixture(t *testing.T) *loginRedirectFixture {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", server.Listener.Addr().String(), "prefix", "/_test/allowed/")
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
		t.Fatal("could not provision redirect identity")
	}
	runtime, err := authcrunch.NewServer(&authcrunch.Config{
		IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}},
		AuthenticationPortals: []*authn.PortalConfig{{
			Name: "login-redirect", IdentityStores: []string{"local"},
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
			t.Errorf("close redirect runtime: %v", err)
		}
	})
	portal, err := runtime.GetPortalByName("login-redirect")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve both allowed and disallowed destinations so a browser can
		// report where it actually landed, independently of the matcher.
		if strings.HasPrefix(r.URL.Path, "/_test/") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<!doctype html><title>Redirect destination</title>")
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Errorf("redirect portal request: %v", err)
		}
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(client.CloseIdleConnections)
	return &loginRedirectFixture{server: server, client: client}
}

func (f *loginRedirectFixture) request(t *testing.T, method, target string, form url.Values) *http.Response {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme+"://"+parsed.Host != f.server.URL {
		t.Fatal("redirect journey left the fixture origin")
	}
	r, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Accept", "text/html")
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal("redirect journey request failed")
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
		t.Fatal("read redirect journey response")
	}
	return response
}

func (f *loginRedirectFixture) follow(t *testing.T, response *http.Response) string {
	t.Helper()
	for range 5 {
		switch response.StatusCode {
		case http.StatusOK:
			return response.Request.URL.String()
		case http.StatusFound, http.StatusSeeOther:
			next, err := response.Location()
			if err != nil {
				t.Fatal("redirect response has no valid location")
			}
			response = f.request(t, http.MethodGet, next.String(), nil)
		default:
			t.Fatalf("redirect journey returned HTTP %d", response.StatusCode)
		}
	}
	t.Fatal("redirect journey exceeded five hops")
	return ""
}

func (f *loginRedirectFixture) login(t *testing.T) {
	t.Helper()
	start := f.request(t, http.MethodPost, f.server.URL+"/login", url.Values{"username": {"alice"}, "realm": {"local"}})
	sandbox, err := start.Location()
	if err != nil || start.StatusCode != http.StatusSeeOther || !strings.HasPrefix(sandbox.Path, "/sandbox/") {
		t.Fatal("login did not enter a sandbox")
	}
	password := f.request(t, http.MethodPost, sandbox.String(), url.Values{"secret": {tests.TestPwd1}})
	if password.StatusCode != http.StatusSeeOther {
		t.Fatal("password checkpoint failed")
	}
	completed := f.request(t, http.MethodGet, sandbox.String(), nil)
	if got := f.follow(t, completed); got != f.server.URL+"/portal" {
		t.Fatalf("login reached %q, want the portal", got)
	}
}

// Complete both initial responses before following either redirect. This is a
// deterministic browser interleaving, with no scheduler or sleep dependency.
func TestE2ELoginRedirectSignedInTabs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []int
	}{
		{name: "single_tab", order: []int{0}},
		{name: "first_tab_follows_first", order: []int{0, 1}},
		{name: "second_tab_follows_first", order: []int{1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginRedirectFixture(t)
			f.login(t)
			destinations := []string{f.server.URL + "/_test/allowed/first?view=one%26two", f.server.URL + "/_test/allowed/second"}
			responses := make([]*http.Response, len(tc.order))
			for i := range responses {
				target := f.server.URL + "/login?redirect_url=" + url.QueryEscape(destinations[i])
				responses[i] = f.request(t, http.MethodGet, target, nil)
			}
			for _, i := range tc.order {
				if got := f.follow(t, responses[i]); got != destinations[i] {
					t.Errorf("tab %d reached %q, want its own destination %q", i+1, got, destinations[i])
				}
			}
		})
	}
}

// The browser, not Go's URL parser, is the independent oracle for the final
// path. Both the explicit flow destination and the legacy cookie must respect
// the configured path restriction after browser URL normalization.
func TestE2ELoginRedirectPathBoundaryBrowser(t *testing.T) {
	f := newLoginRedirectFixture(t)
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
	driver := exec.CommandContext(ctx, "node", "ui/testdata/login_redirect_browser_e2e.cjs", endpoint, f.server.URL)
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("redirect browser journey failed: %v\n%s", err, output)
	}
	var result struct {
		Cases []struct {
			Name     string `json:"name"`
			Target   string `json:"target"`
			Actual   string `json:"actual"`
			Expected string `json:"expected"`
			Status   int    `json:"status"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(output, &result); err != nil || len(result.Cases) != 12 {
		t.Fatal("browser did not return all redirect cases")
	}
	for _, tc := range result.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Expected != "" {
				if tc.Status != http.StatusOK || tc.Actual != tc.Expected {
					t.Errorf("allowed destination %q reached %q (HTTP %d), want %q", tc.Target, tc.Actual, tc.Status, tc.Expected)
				}
				return
			}
			// Accept either a local error or the usual portal fallback. The
			// test specifies the trust boundary, not the rejection renderer.
			if tc.Actual != f.server.URL+"/portal" && tc.Actual != f.server.URL+"/portal?redirect_url=" && !strings.HasPrefix(tc.Actual, f.server.URL+"/login?") {
				t.Errorf("untrusted browser destination reached: input %q, actual %q", tc.Target, tc.Actual)
			}
			if tc.Status != http.StatusOK && tc.Status != http.StatusBadRequest && tc.Status != http.StatusForbidden {
				t.Errorf("unexpected rejection status HTTP %d", tc.Status)
			}
		})
	}
}

func TestE2ELoginDestinationBoundsAndEmptyChoice(t *testing.T) {
	for _, size := range []int{0, 2049, 8000, 16384, 16385} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := newLoginRedirectFixture(t)
			destination := ""
			if size != 0 {
				prefix := f.server.URL + "/_test/allowed/"
				destination = prefix + strings.Repeat("x", size-len(prefix))
			}
			endpoint := f.server.URL + "/login?redirect_url=" + url.QueryEscape(destination)
			response, err := f.client.Get(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				t.Fatal("login rendering", err)
			}
			for _, cookie := range response.Cookies() {
				if cookie.Name == "AUTHP_REDIRECT_URL" && size > 2048 {
					t.Fatal("oversized destination written to cookie")
				}
			}
			action := regexp.MustCompile(`<form[^>]*action="([^"]+)"`).FindSubmatch(body)
			if len(action) != 2 {
				t.Fatal("missing form")
			}
			target, err := url.Parse(html.UnescapeString(string(action[1])))
			if err != nil {
				t.Fatal(err)
			}
			origin, _ := url.Parse(f.server.URL)
			target = origin.ResolveReference(target)
			f.client.Jar.SetCookies(origin, []*http.Cookie{{Name: "AUTHP_REDIRECT_URL", Value: f.server.URL + "/_test/allowed/another-tab", Path: "/"}})
			start := f.request(t, http.MethodPost, target.String(), url.Values{"username": {"alice"}, "realm": {"local"}})
			sandbox, err := start.Location()
			if err != nil {
				t.Fatal(err)
			}
			password := f.request(t, http.MethodPost, sandbox.String(), url.Values{"secret": {tests.TestPwd1}})
			if password.StatusCode != 303 {
				t.Fatal("password checkpoint failed")
			}
			complete := f.request(t, http.MethodGet, sandbox.String(), nil)
			// Another tab may write its cookie after the login's 303 but before
			// this tab follows it. The explicit empty marker must survive that gap.
			if size == 0 || size > 16384 {
				f.client.Jar.SetCookies(origin, []*http.Cookie{{Name: "AUTHP_REDIRECT_URL", Value: f.server.URL + "/_test/allowed/between-redirects", Path: "/"}})
			}
			want := destination
			if size == 0 || size > 16384 {
				want = f.server.URL + "/portal?redirect_url="
			}
			if got := f.follow(t, complete); got != want {
				t.Fatalf("size %d returned to another destination", size)
			}
		})
	}
}
