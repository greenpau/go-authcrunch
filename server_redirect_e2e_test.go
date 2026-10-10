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
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// HTTP/3 must reach the gatekeeper through quic-go's real request parser. Merely
// setting ProtoMajor on a net/http request would miss the original regression.
func serveRedirectHTTP3(t *testing.T, server *httptest.Server) {
	t.Helper()
	conn, err := net.ListenPacket("udp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{Handler: server.Config.Handler, TLSConfig: server.TLS.Clone()}
	done := make(chan error, 1)
	go func() { done <- h3.Serve(conn) }()
	t.Cleanup(func() {
		if err := h3.Close(); err != nil {
			t.Errorf("close HTTP/3 server: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Errorf("close HTTP/3 socket: %v", err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP/3 server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})
}

type redirectLoginFixture struct {
	client              *http.Client
	application, portal string
	protocol            int
}

func newRedirectLoginFixture(t *testing.T, protocol int, authPath string) *redirectLoginFixture {
	t.Helper()
	appServer := httptest.NewUnstartedServer(nil)
	portalServer := httptest.NewUnstartedServer(nil)
	t.Cleanup(appServer.Close)
	t.Cleanup(portalServer.Close)
	f := &redirectLoginFixture{
		application: "https://" + appServer.Listener.Addr().String(),
		portal:      "https://" + portalServer.Listener.Addr().String(),
		protocol:    protocol,
	}
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", appServer.Listener.Addr().String(), "prefix", "/")
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
		t.Fatal("provision redirect test identity")
	}
	keys := []string{"crypto key redirect sign-verify from file testdata/rskeys/test_2_pri.pem"}
	runtime, err := authcrunch.NewServer(&authcrunch.Config{
		IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}},
		AuthenticationPortals: []*authn.PortalConfig{{
			Name: "portal", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: keys,
			TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted},
		}},
		AuthorizationPolicies: []*authz.PolicyConfig{{
			Name: "policy", AuthURLPath: f.portal + authPath, RawCryptoKeyStoreConfig: keys,
			AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
		}},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		appServer.Close()
		portalServer.Close()
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	portal, err := runtime.GetPortalByName("portal")
	if err != nil {
		t.Fatal(err)
	}
	gate, err := runtime.GetGatekeeperByName("policy")
	if err != nil {
		t.Fatal(err)
	}
	portalServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Errorf("redirect portal request: %v", err)
		}
	})
	appServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != protocol || (protocol == 3 && (!r.URL.IsAbs() || !strings.HasPrefix(r.RequestURI, "/"))) {
			t.Errorf("unexpected server request representation: protocol=%s URL=%q RequestURI=%q", r.Proto, r.URL.String(), r.RequestURI)
			http.Error(w, "unexpected protocol", http.StatusBadRequest)
			return
		}
		ar := requests.NewAuthorizationRequest()
		// An unauthenticated request already has a redirect response. Only
		// the explicit Authorized outcome may execute the application.
		if err := gate.Authenticate(w, r, ar); err != nil || !ar.Response.Authorized {
			return
		}
		_, _ = io.WriteString(w, "protected resource: "+r.RequestURI)
	})
	appServer.EnableHTTP2 = protocol == 2
	portalServer.EnableHTTP2 = protocol == 2
	appServer.StartTLS()
	portalServer.StartTLS()
	f.client = appServer.Client()
	if protocol == 3 {
		serveRedirectHTTP3(t, appServer)
		serveRedirectHTTP3(t, portalServer)
		tlsConfig := f.client.Transport.(*http.Transport).TLSClientConfig.Clone()
		transport := &http3.Transport{TLSClientConfig: tlsConfig}
		f.client.Transport = transport
		t.Cleanup(func() {
			if err := transport.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(f.client.CloseIdleConnections)
	f.client.Timeout = 10 * time.Second
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return f
}

func (f *redirectLoginFixture) request(t *testing.T, method, target string, form url.Values, wantStatus int) (*http.Response, string) {
	t.Helper()
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
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("redirect journey request: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal("read redirect journey response")
	}
	if resp.StatusCode != wantStatus || resp.ProtoMajor != f.protocol {
		t.Fatalf("response = %s %d, want HTTP/%d %d", resp.Proto, resp.StatusCode, f.protocol, wantStatus)
	}
	return resp, string(data)
}

func TestE2EServerAuthorizationLoginRedirectProtocols(t *testing.T) {
	for _, protocol := range []struct {
		name  string
		major int
	}{{"HTTP1", 1}, {"HTTP2", 2}, {"HTTP3", 3}} {
		t.Run(protocol.name, func(t *testing.T) {
			f := newRedirectLoginFixture(t, protocol.major, "/auth/login")
			for _, target := range []string{"/", "/files/a%2fb?x=one%26two&x=three+four", "//other.example/private"} {
				t.Run(target, func(t *testing.T) {
					var err error
					f.client.Jar, err = cookiejar.New(nil)
					if err != nil {
						t.Fatal(err)
					}
					wantReturn := f.application + target
					redirect, _ := f.request(t, http.MethodGet, wantReturn, nil, http.StatusFound)
					loginURL, err := url.Parse(redirect.Header.Get("Location"))
					if err != nil {
						t.Fatal(err)
					}
					if loginURL.Scheme+"://"+loginURL.Host+loginURL.Path != f.portal+"/auth/login" {
						t.Fatalf("unexpected portal destination %q", loginURL.String())
					}
					if got := loginURL.Query().Get("redirect_url"); got != wantReturn {
						t.Fatalf("redirect_url = %q, want %q", got, wantReturn)
					}
					f.request(t, http.MethodGet, loginURL.String(), nil, http.StatusOK)
					start, _ := f.request(t, http.MethodPost, f.portal+"/auth/login", url.Values{"username": {"alice"}, "realm": {"local"}}, http.StatusSeeOther)
					sandbox, err := start.Location()
					if err != nil {
						t.Fatal(err)
					}
					f.request(t, http.MethodPost, sandbox.String(), url.Values{"secret": {tests.TestPwd1}}, http.StatusSeeOther)
					completed, _ := f.request(t, http.MethodGet, sandbox.String(), nil, http.StatusSeeOther)
					if got := completed.Header.Get("Location"); got != wantReturn {
						t.Fatalf("post-login destination = %q, want %q", got, wantReturn)
					}
					_, body := f.request(t, http.MethodGet, completed.Header.Get("Location"), nil, http.StatusOK)
					if body != "protected resource: "+target {
						t.Fatalf("returned resource = %q, want original protected resource", body)
					}
				})
			}
		})
	}
}

var loginFormAction = regexp.MustCompile(`<form[^>]*action="([^"]*/login[^"]*)"[^>]*method="POST"`)

var loginReturnURL = regexp.MustCompile(`login\.js"[^>]*data-return-url="([^"]*)"`)

var loginProbeURL = regexp.MustCompile(`login\.js"[^>]*data-whoami="([^"]*)"`)

// redirectTab is one browser tab: its protected destination and the login page
// it was left on. The tabs of one test share a cookie jar, as a browser's do.
type redirectTab struct {
	target   string
	loginURL *url.URL
	form     *url.URL
	// returnURL is where the page's script sends the tab once the browser is
	// signed in elsewhere.
	returnURL string
	probeURL  string
}

// follow requests target and expects a redirect, returning its absolute destination.
func (f *redirectLoginFixture) follow(t *testing.T, method string, target *url.URL, form url.Values) *url.URL {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target.String(), body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("redirect journey request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Fatalf("%s %s = %d, want a redirect", method, target.Path, resp.StatusCode)
	}
	next, err := target.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return next
}

// leavePortal follows a tab's redirects while they stay on the portal, as a
// browser would: a portal hop such as /login to /portal is not where the tab
// lands, but a portal page that renders is.
func (f *redirectLoginFixture) leavePortal(t *testing.T, next *url.URL) *url.URL {
	t.Helper()
	for i := 0; strings.HasPrefix(next.String(), f.portal+"/"); i++ {
		if i > 3 {
			t.Fatalf("tab kept redirecting within the portal, stopped at %s", next)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, next.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatalf("redirect journey request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			return next
		}
		location, err := next.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		next = location
	}
	return next
}

// openTab walks a tab from its protected destination through the gate and the
// portal root to the rendered login page, keeping only what a browser would:
// the URL it ended on and the form target the page offers.
func (f *redirectLoginFixture) openTab(t *testing.T, target string) *redirectTab {
	t.Helper()
	start, err := url.Parse(f.application + target)
	if err != nil {
		t.Fatal(err)
	}
	next := f.follow(t, http.MethodGet, start, nil)
	for i := 0; next.Path != "/auth/login"; i++ {
		if i > 3 {
			t.Fatalf("tab %s never reached the login page, stopped at %s", target, next)
		}
		next = f.follow(t, http.MethodGet, next, nil)
	}
	return f.loadLogin(t, f.application+target, next)
}

// loadLogin renders the login page at loginURL in a tab heading for target.
func (f *redirectLoginFixture) loadLogin(t *testing.T, target string, loginURL *url.URL) *redirectTab {
	t.Helper()
	tab := &redirectTab{target: target, loginURL: loginURL}
	_, page := f.request(t, http.MethodGet, loginURL.String(), nil, http.StatusOK)
	m := loginFormAction.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("login page for tab %s has no login form", target)
	}
	var err error
	tab.form, err = loginURL.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if m := loginReturnURL.FindStringSubmatch(page); m != nil {
		tab.returnURL = html.UnescapeString(m[1])
	}
	if m := loginProbeURL.FindStringSubmatch(page); m != nil {
		tab.probeURL = html.UnescapeString(m[1])
	}
	return tab
}

// probe asks whoami as a waiting login page's script does, returning the status.
func (f *redirectLoginFixture) probe(t *testing.T) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.portal+"/auth/whoami?probe=login", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("login probe request: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// signIn logs alice in through a login form and returns where the tab lands.
func (f *redirectLoginFixture) signIn(t *testing.T, form *url.URL) *url.URL {
	t.Helper()
	sandbox := f.follow(t, http.MethodPost, form, url.Values{"username": {"alice"}, "realm": {"local"}})
	f.follow(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}})
	return f.leavePortal(t, f.follow(t, http.MethodGet, sandbox, nil))
}

// A browser that reaches the login from several tabs at once must send each tab
// back to its own page. The gate points at the portal root, as deployments do,
// which is where a tab's destination used to fall out of its URL into the one
// shared redirect cookie, so the last tab to load won for every tab.
func TestE2EServerAuthorizationLoginRedirectPerTab(t *testing.T) {
	for _, protocol := range []struct {
		name  string
		major int
	}{{"HTTP1", 1}, {"HTTP2", 2}, {"HTTP3", 3}} {
		t.Run(protocol.name, func(t *testing.T) {
			f := newRedirectLoginFixture(t, protocol.major, "/auth/")
			var err error
			f.client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			first := f.openTab(t, "/tab/first%2fpart?x=one%26two&x=three+four")
			reloaded := f.openTab(t, "/tab/reloaded?view=one%26two")
			resubmitted := f.openTab(t, "/tab/resubmitted")

			for _, tab := range []*redirectTab{first, reloaded, resubmitted} {
				if tab.returnURL != tab.target || tab.probeURL != "/auth/whoami?probe=login" {
					t.Errorf("tab %s page sends a signed-in browser to %q", tab.target, tab.returnURL)
				}
			}
			// The page script asks whoami whether the browser is signed in.
			if got := f.probe(t); got != http.StatusUnauthorized {
				t.Fatalf("login probe before the login returned HTTP %d, want 401", got)
			}

			// Going back from the password step returns a tab to its own login
			// page, destination included.
			sandbox := f.follow(t, http.MethodPost, reloaded.form, url.Values{"username": {"alice"}, "realm": {"local"}})
			if back := f.follow(t, http.MethodGet, sandbox.JoinPath("terminate"), nil); back.String() != reloaded.loginURL.String() {
				t.Errorf("tab %s went back to %s, want %s", reloaded.target, back, reloaded.loginURL)
			}

			// Log in on the first tab, through the form its own page offered.
			landed := map[string]*url.URL{first.target: f.signIn(t, first.form)}

			// The other tabs still show the login: one is reloaded, one submitted.
			landed[reloaded.target] = f.leavePortal(t, f.follow(t, http.MethodGet, reloaded.loginURL, nil))
			landed[resubmitted.target] = f.leavePortal(t, f.follow(t, http.MethodPost, resubmitted.form, url.Values{"username": {"alice"}, "realm": {"local"}}))
			if got := f.probe(t); got != http.StatusOK {
				t.Fatalf("login probe after the login returned HTTP %d, want 200", got)
			}

			for _, tab := range []*redirectTab{first, reloaded, resubmitted} {
				if got := landed[tab.target].String(); got != tab.target {
					t.Errorf("tab %s landed on %q", tab.target, got)
					continue
				}
				_, body := f.request(t, http.MethodGet, tab.target, nil, http.StatusOK)
				if want := "protected resource: " + strings.TrimPrefix(tab.target, f.application); body != want {
					t.Errorf("tab %s got %q, want %q", tab.target, body, want)
				}
			}
		})
	}
}

// Long destinations remain bound to the login without a browser cookie. Values
// outside the bound or trust policy select the portal even when another tab
// changes the shared cookie before authentication completes.
func TestE2EServerAuthorizationLoginRedirectBoundaries(t *testing.T) {
	f := newRedirectLoginFixture(t, 1, "/auth/")
	var err error
	f.client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tab := f.openTab(t, "/tab/"+strings.Repeat("a", 8000))
	if tab.loginURL.Query().Get("redirect_url") != tab.target || tab.form.Query().Get("redirect_url") != tab.target || tab.returnURL != tab.target {
		t.Fatal("long destination was not retained in the page and form")
	}
	for _, c := range f.client.Jar.Cookies(tab.loginURL) {
		if c.Name == "AUTHP_REDIRECT_URL" {
			t.Fatal("long destination was written into a redirect cookie")
		}
	}
	f.client.Jar.SetCookies(tab.loginURL, []*http.Cookie{{Name: "AUTHP_REDIRECT_URL", Value: f.application + "/another-tab", Path: "/auth"}})
	if got := f.signIn(t, tab.form); got.String() != tab.target {
		t.Fatalf("long destination lost to another tab, landed on %.80s", got)
	}
	f.request(t, http.MethodGet, tab.target, nil, http.StatusOK)

	for _, query := range []string{
		"redirect_url=" + url.QueryEscape("https://untrusted.example.test/tab"),
		"redirect_url=" + url.QueryEscape(f.application+"/tab/"+strings.Repeat("a", 17000)),
		"redirect_url=",
		"redirect_url=%zz",
		"redirect_url=%zz&redirect_url=" + url.QueryEscape(f.application+"/second"),
		"redirect_url=" + f.application + "/first;ignored=1&redirect_url=" + url.QueryEscape(f.application+"/second"),
	} {
		f.client.Jar, err = cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		login, err := url.Parse(f.portal + "/auth/login?" + query)
		if err != nil {
			t.Fatal(err)
		}
		tab = f.loadLogin(t, "", login)
		if tab.form.String() != f.portal+"/auth/login?redirect_url=" || tab.returnURL != "/auth/portal?redirect_url=" {
			t.Fatalf("rejected destination did not bind an empty choice: form %s, page destination %q", tab.form, tab.returnURL)
		}
		f.client.Jar.SetCookies(login, []*http.Cookie{{Name: "AUTHP_REDIRECT_URL", Value: f.application + "/another-tab", Path: "/auth"}})
		if got := f.signIn(t, tab.form); got.String() != f.portal+"/auth/portal?redirect_url=" {
			t.Fatalf("rejected destination login landed on %s", got)
		}
		// Submitting the original URL again while signed in must stay isolated.
		f.client.Jar.SetCookies(login, []*http.Cookie{{Name: "AUTHP_REDIRECT_URL", Value: f.application + "/another-tab", Path: "/auth"}})
		if got := f.leavePortal(t, f.follow(t, http.MethodPost, login, url.Values{"username": {"alice"}, "realm": {"local"}})); got.String() != f.portal+"/auth/portal?redirect_url=" {
			t.Fatalf("signed-in rejected submission landed on %s", got)
		}
	}
}

// A fresh login started with a destination, as re-authentication and approval
// flows start one, stays fresh with its destination when the user goes back
// from the password step, and its page still does not watch for other tabs.
func TestE2EServerAuthorizationLoginRedirectFreshBack(t *testing.T) {
	f := newRedirectLoginFixture(t, 1, "/auth/")
	var err error
	f.client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	target := f.application + "/tab/fresh?x=one%26two"
	login, err := url.Parse(f.portal + "/auth/login?" + url.Values{"fresh": {"1"}, "redirect_url": {target}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	tab := f.loadLogin(t, target, login)
	// html/template escapes the query with lowercase hex; compare its values.
	if tab.form.Path != login.Path || tab.form.Query().Encode() != login.Query().Encode() || tab.probeURL != "" {
		t.Fatalf("fresh login page posts to %s and probes %q", tab.form, tab.probeURL)
	}
	sandbox := f.follow(t, http.MethodPost, tab.form, url.Values{"username": {"alice"}, "realm": {"local"}})
	back := f.follow(t, http.MethodGet, sandbox.JoinPath("terminate"), nil)
	if back.String() != login.String() {
		t.Fatalf("going back from a fresh login reached %s, want %s", back, login)
	}
	tab = f.loadLogin(t, target, back)
	if got := f.signIn(t, tab.form); got.String() != target {
		t.Fatalf("fresh login landed on %s, want %s", got, target)
	}
}
