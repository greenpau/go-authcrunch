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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// The sentinel proves targeted cleanup does not expire unrelated credentials.
const refererCleanupSentinelCookie = "REFERER_CLEANUP_SENTINEL"

type refererCleanupE2EFixture struct {
	server       *httptest.Server
	client       *http.Client
	mount        string
	cookieName   string
	cookiePath   string
	returnURL    string
	cookieMaxAge int
}

type refererCleanupE2EResponse struct {
	status int
	header http.Header
	body   []byte
}

func newRefererCleanupE2EFixture(t *testing.T, mount string, cookieDirectives ...string) *refererCleanupE2EFixture {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	returnURL := origin + "/_test/referer-cleanup/accepted"
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", server.Listener.Addr().String(), "exact", "/_test/referer-cleanup/accepted")
	if err != nil {
		t.Fatal(err)
	}
	statements := make([]string, 0, len(cookieDirectives))
	for _, directive := range cookieDirectives {
		statements = append(statements, cfgutil.EncodeArgs(strings.Fields(directive)))
	}
	cookies, err := cookieparser.NewCookieConfigFromDirectives(statements)
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
		t.Fatal("could not provision referer-cleanup identity")
	}
	portalConfig := &authn.PortalConfig{
		Name: "referer-cleanup", IdentityStores: []string{"referer-cleanup-local"}, CookieConfig: cookies,
		RawCryptoKeyStoreConfig:        []string{"crypto key rsa-current sign-verify from file ../../testdata/rskeys/test_2_pri.pem"},
		TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted},
	}
	config := &authcrunch.Config{
		IdentityStores:        []*ids.IdentityStoreConfig{{Name: "referer-cleanup-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}},
		AuthenticationPortals: []*authn.PortalConfig{portalConfig},
	}
	runtime, err := authcrunch.NewServer(config, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	var client *http.Client
	t.Cleanup(func() {
		if client != nil {
			client.CloseIdleConnections()
		}
		server.Close()
		if err := runtime.Close(); err != nil {
			t.Errorf("close referer-cleanup runtime: %v", err)
		}
	})
	portal, err := runtime.GetPortalByName("referer-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_test/referer-cleanup/blank":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><title>Referer cleanup</title>"))
		case "/_test/referer-cleanup/accepted":
			w.WriteHeader(http.StatusNoContent)
		case "/_test/referer-cleanup/sentinel":
			http.SetCookie(w, &http.Cookie{Name: refererCleanupSentinelCookie, Value: "present", Path: "/", Secure: true, HttpOnly: true})
		case "/_test/referer-cleanup/old-delete":
			// This negative control models the rejected header which motivated the
			// cleanup fix: __Host- deletion without Secure cannot replace a cookie.
			http.SetCookie(w, &http.Cookie{Name: cookies.RefererCookieName, Value: "delete", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true})
		default:
			if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
				t.Errorf("referer-cleanup portal request failed: %v", err)
			}
		}
	})
	server.StartTLS()
	client = server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cookiePath := strings.TrimSuffix(mount, "/")
	if cookiePath == "" {
		cookiePath = "/"
	}
	return &refererCleanupE2EFixture{
		server: server, client: client, mount: strings.TrimSuffix(mount, "/"), cookieName: cookies.RefererCookieName,
		cookiePath: cookiePath, returnURL: returnURL, cookieMaxAge: cookies.Lifetime,
	}
}

func (f *refererCleanupE2EFixture) path(endpoint string) string {
	if f.mount == "" {
		return endpoint
	}
	return f.mount + endpoint
}

func (f *refererCleanupE2EFixture) request(t *testing.T, method, target string, form url.Values) refererCleanupE2EResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.server.URL + target
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal("referer-cleanup HTTPS request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal("referer-cleanup response read failed")
	}
	return refererCleanupE2EResponse{status: response.StatusCode, header: response.Header, body: responseBody}
}

func (f *refererCleanupE2EFixture) issueRefererCookie(t *testing.T, wantStatus int) refererCleanupE2EResponse {
	t.Helper()
	target := f.path("/login") + "?redirect_url=" + url.QueryEscape(f.returnURL)
	response := f.request(t, http.MethodGet, target, nil)
	if response.status != wantStatus {
		t.Fatalf("referer cookie issuance returned HTTP %d, want %d", response.status, wantStatus)
	}
	var issued []*http.Cookie
	for _, raw := range response.header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(raw)
		if err != nil {
			t.Fatal("portal emitted malformed Set-Cookie")
		}
		if cookie.Name == f.cookieName {
			issued = append(issued, cookie)
		}
	}
	if len(issued) != 1 {
		t.Fatalf("referer issuance emitted %d matching cookies, want 1", len(issued))
	}
	cookie := issued[0]
	if cookie.Value != f.returnURL || cookie.Path != f.cookiePath || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != 0 || cookie.MaxAge != f.cookieMaxAge {
		t.Fatalf("referer issuance attributes: value=%q path=%q domain=%q secure=%t http_only=%t same_site=%d max_age=%d; want value=%q path=%q host-only secure HTTP-only default-same-site max_age=%d", cookie.Value, cookie.Path, cookie.Domain, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.MaxAge, f.returnURL, f.cookiePath, f.cookieMaxAge)
	}
	if !f.hasCookie(t, f.cookieName) {
		t.Fatal("browser jar did not store the issued referer cookie")
	}
	return response
}

func (f *refererCleanupE2EFixture) login(t *testing.T) refererCleanupE2EResponse {
	t.Helper()
	start := f.request(t, http.MethodPost, f.path("/login"), url.Values{"username": {"alice"}, "realm": {"local"}})
	if start.status != http.StatusSeeOther {
		t.Fatalf("login start returned HTTP %d", start.status)
	}
	sandbox := start.header.Get("Location")
	password := f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}})
	if password.status != http.StatusSeeOther {
		t.Fatalf("password checkpoint returned HTTP %d", password.status)
	}
	completed := f.request(t, http.MethodGet, sandbox, nil)
	if completed.status != http.StatusSeeOther {
		t.Fatalf("login completion returned HTTP %d", completed.status)
	}
	return completed
}

func (f *refererCleanupE2EFixture) overwriteRefererCookie(t *testing.T, value string) {
	t.Helper()
	target, err := url.Parse(f.server.URL + f.path("/portal"))
	if err != nil {
		t.Fatal(err)
	}
	f.client.Jar.SetCookies(target, []*http.Cookie{{
		Name: f.cookieName, Value: value, Path: f.cookiePath, Secure: true, HttpOnly: true,
	}})
	if !f.hasCookie(t, f.cookieName) {
		t.Fatal("browser jar did not retain the replacement referer cookie")
	}
}

func (f *refererCleanupE2EFixture) hasCookie(t *testing.T, name string) bool {
	t.Helper()
	target, err := url.Parse(f.server.URL + f.path("/portal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range f.client.Jar.Cookies(target) {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func (f *refererCleanupE2EFixture) assertDeletion(t *testing.T, response refererCleanupE2EResponse) {
	t.Helper()
	var deleted []*http.Cookie
	for _, raw := range response.header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(raw)
		if err != nil {
			t.Fatal("portal emitted malformed Set-Cookie")
		}
		if cookie.Name == f.cookieName {
			deleted = append(deleted, cookie)
		}
	}
	if len(deleted) != 1 {
		t.Fatalf("referer cleanup emitted %d matching cookies, want 1", len(deleted))
	}
	cookie := deleted[0]
	if cookie.Value != "delete" || cookie.Path != f.cookiePath || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != 0 || cookie.MaxAge != -1 || !cookie.Expires.Equal(time.Unix(0, 0)) {
		t.Fatal("referer deletion changed issuance scope or omitted browser expiry and security attributes")
	}
	if f.hasCookie(t, f.cookieName) {
		t.Fatal("browser jar retained the deleted referer cookie")
	}
	if !f.hasCookie(t, refererCleanupSentinelCookie) {
		t.Fatal("referer cleanup removed an unrelated cookie")
	}
}

func TestE2ERefererCookieCleanup(t *testing.T) {
	f := newRefererCleanupE2EFixture(t, "/tenant/auth", "cookie prefix TENANT", "cookie lifetime 120")
	target, err := url.Parse(f.server.URL + f.path("/portal"))
	if err != nil {
		t.Fatal(err)
	}
	f.client.Jar.SetCookies(target, []*http.Cookie{{Name: refererCleanupSentinelCookie, Value: "present", Path: f.cookiePath, Secure: true, HttpOnly: true}})

	t.Run("successful login grant", func(t *testing.T) {
		f.issueRefererCookie(t, http.StatusOK)
		response := f.login(t)
		if response.header.Get("Location") != f.returnURL {
			t.Fatalf("login returned to %q, want trusted destination", response.header.Get("Location"))
		}
		f.assertDeletion(t, response)
	})

	t.Run("authenticated portal trusted redirect", func(t *testing.T) {
		f.issueRefererCookie(t, http.StatusFound)
		response := f.request(t, http.MethodGet, f.path("/portal"), nil)
		if response.status != http.StatusSeeOther || response.header.Get("Location") != f.returnURL {
			t.Fatalf("portal returned HTTP %d to %q, want trusted redirect", response.status, response.header.Get("Location"))
		}
		f.assertDeletion(t, response)
	})

	for _, tc := range []struct {
		name, value string
	}{
		{name: "untrusted redirect", value: "https://evil.example.test/return"},
		{name: "malformed redirect", value: "http://[::1"},
	} {
		t.Run("authenticated portal rejects "+tc.name, func(t *testing.T) {
			f.issueRefererCookie(t, http.StatusFound)
			f.overwriteRefererCookie(t, tc.value)
			response := f.request(t, http.MethodGet, f.path("/portal"), nil)
			if response.status != http.StatusOK || !strings.Contains(string(response.body), "Applications") {
				t.Fatalf("portal did not render after ignoring %s", tc.name)
			}
			f.assertDeletion(t, response)
		})
	}
}

func TestE2ERefererCookieCleanupBrowser(t *testing.T) {
	f := newRefererCleanupE2EFixture(t, "", "cookie referer name __Host-REFERER")
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
	params, err := json.Marshal(map[string]string{
		"origin": f.server.URL, "referer": f.cookieName, "sentinel": refererCleanupSentinelCookie, "return_url": f.returnURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/cookie_cleanup_browser_e2e.cjs", endpoint, string(params))
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("referer cleanup browser regression failed: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm referer cleanup")
	}
}
