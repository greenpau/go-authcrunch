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

package authn

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cache"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

var (
	regexpLoginFormAction   = regexp.MustCompile(`<form[^>]*action="([^"]*)" method="POST"`)
	regexpLoginProviderLink = regexp.MustCompile(`<a href="(oauth2/upstream[^"]*)"`)
)

// newLoginScreenPortal returns a portal that renders the basic login page.
func newLoginScreenPortal(t *testing.T, trusted *redirects.RedirectURIMatchConfig) *Portal {
	t.Helper()
	p := newRefererCleanupPortal(t, trusted)
	p.loginOptions = map[string]any{
		"authenticators": []map[string]string{
			{"realm": "local", "text": "Local"},
			{"realm": "upstream", "text": "Upstream", "endpoint": "oauth2/upstream", "login_return_url_enabled": "yes"},
		},
		"authenticators_required":   "yes",
		"default_realm":             "local",
		"form_required":             "yes",
		"hide_contact_support_link": "yes",
		"hide_forgot_username_link": "yes",
		"hide_links":                "yes",
		"hide_register_link":        "yes",
		"identity_required":         "yes",
		"realm_dropdown_required":   "no",
		"realms":                    []map[string]string{{"realm": "local", "default": "yes"}},
	}
	p.sessions = cache.NewSessionCache()
	p.sessions.Run()
	t.Cleanup(p.sessions.Stop)
	return p
}

func newLoginReturnTrust(t *testing.T) *redirects.RedirectURIMatchConfig {
	t.Helper()
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.test", "prefix", "/")
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func TestTrustedLoginReturnURL(t *testing.T) {
	trusted := newLoginReturnTrust(t)
	// A domain pattern that also accepts an empty host.
	optionalHost, err := redirects.NewRedirectURIMatchConfig("regex", `^(app\.example\.test)?$`, "prefix", "/")
	if err != nil {
		t.Fatal(err)
	}
	base := "https://app.example.test/"
	longest := base + strings.Repeat("a", maxLoginReturnURLLength-len(base))
	// Within the bound as received, but re-encoded past it: each ü becomes %C3%BC.
	encoded := base + "?q=" + strings.Repeat("ü", (maxLoginReturnURLLength-len(base)-3)/2)
	for _, tc := range []struct {
		name    string
		raw     string
		trusted []*redirects.RedirectURIMatchConfig
		want    string
	}{
		{name: "trusted", raw: "https://app.example.test/tab?x=one%26two", trusted: []*redirects.RedirectURIMatchConfig{trusted}, want: "https://app.example.test/tab?x=one%26two"},
		{name: "login hint stripped", raw: "https://app.example.test/tab?login_hint=a%40example.test&x=1", trusted: []*redirects.RedirectURIMatchConfig{trusted}, want: "https://app.example.test/tab?x=1"},
		{name: "longest carried", raw: longest, trusted: []*redirects.RedirectURIMatchConfig{trusted}, want: longest},
		{name: "one byte too long", raw: longest + "a", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "too long once re-encoded", raw: encoded, trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "plain http", raw: "http://app.example.test/tab", trusted: []*redirects.RedirectURIMatchConfig{trusted}, want: "http://app.example.test/tab"},
		{name: "script scheme", raw: "javascript://app.example.test/%0Aalert(1)", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "other scheme", raw: "ftp://app.example.test/tab", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "untrusted host", raw: "https://evil.example.test/tab", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "trusted host in path", raw: "https://evil.example.test/app.example.test/", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "relative", raw: "/tab", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		// A browser takes the first path segment of these for the host.
		{name: "no host", raw: "https:///app.example.test/tab", trusted: []*redirects.RedirectURIMatchConfig{optionalHost}},
		{name: "no authority", raw: "https:/app.example.test/tab", trusted: []*redirects.RedirectURIMatchConfig{optionalHost}},
		{name: "host the pattern accepts", raw: "https://app.example.test/tab", trusted: []*redirects.RedirectURIMatchConfig{optionalHost}, want: "https://app.example.test/tab"},
		// A browser removes dot segments before it requests the URL.
		{name: "dot segments", raw: "https://app.example.test/tab/../other", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "encoded dot segments", raw: "https://app.example.test/tab/%2e%2E/other", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "malformed", raw: "https://app.example.test/%zz", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "empty", raw: "", trusted: []*redirects.RedirectURIMatchConfig{trusted}},
		{name: "no trusted destinations", raw: "https://app.example.test/tab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Portal{config: &PortalConfig{TrustedLoginRedirectURIConfigs: tc.trusted}}
			if got := p.trustedLoginReturnURL(tc.raw); got != tc.want {
				t.Fatalf("trustedLoginReturnURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestLoginPageLocation(t *testing.T) {
	destination := "https://app.example.test/a/../b?x=one%26two"
	for _, tc := range []struct {
		returnURL string
		fresh     bool
		want      string
	}{
		{want: "/login"},
		{fresh: true, want: "/login?fresh=1"},
		{returnURL: destination, want: "/login?redirect_url=" + url.QueryEscape(destination)},
		{returnURL: destination, fresh: true, want: "/login?fresh=1&redirect_url=" + url.QueryEscape(destination)},
	} {
		got := loginPageLocation(tc.returnURL, tc.fresh)
		if got != tc.want {
			t.Errorf("loginPageLocation(%q, %t) = %q, want %q", tc.returnURL, tc.fresh, got, tc.want)
		}
		// handleHTTPRedirect joins the location onto the portal path; the
		// encoded query holds no slash for path cleaning to rewrite.
		if joined := path.Join("/auth", got); joined != "/auth"+got {
			t.Errorf("joined login location %q, want %q", joined, "/auth"+got)
		}
	}
}

// Only the first redirect_url counts, as for the redirect cookie: a trusted
// value appended after an untrusted one does not choose the destination.
func TestLoginReturnURLUsesFirstValue(t *testing.T) {
	p := newRefererCleanupPortal(t, newLoginReturnTrust(t))
	for _, tc := range []struct {
		query string
		want  string
	}{
		{query: "redirect_url=" + url.QueryEscape("https://app.example.test/first") + "&redirect_url=" + url.QueryEscape("https://app.example.test/second"), want: "https://app.example.test/first"},
		{query: "redirect_url=" + url.QueryEscape("https://evil.example.test/") + "&redirect_url=" + url.QueryEscape("https://app.example.test/second")},
		{query: "redirect_url=%zz&redirect_url=" + url.QueryEscape("https://app.example.test/second")},
		{query: "redirect_url=https://app.example.test/first;ignored=1&redirect_url=" + url.QueryEscape("https://app.example.test/second")},
		{query: "redirect_url="},
		{query: ""},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://login.example.test/auth/login?"+tc.query, nil)
		if got := p.loginReturnURL(r, requests.NewRequest()); got != tc.want {
			t.Errorf("loginReturnURL(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}
}

func TestLoginDestinationQueryPreservesMalformedChoice(t *testing.T) {
	for _, tc := range []struct {
		query   string
		want    string
		present bool
	}{
		{query: "other=value"},
		{query: "redirect_url", present: true},
		{query: "redirect_url=&redirect_url=later", present: true},
		{query: "redirect_url=%zz&redirect_url=later", present: true},
		{query: "redirect_url=first;ignored=1&redirect_url=later", present: true},
		{query: "%72edirect_url=%zz&redirect_url=later", present: true},
		{query: "%72edirect_url=first%3Bkept&redirect_url=later", want: "first;kept", present: true},
		{query: "other=%zz&redirect_url=first+value", want: "first value", present: true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/login?"+tc.query, nil)
			got, present := loginDestinationQuery(r)
			if got != tc.want || present != tc.present || hasLoginDestination(r) != tc.present {
				t.Fatalf("destination=(%q,%t), want (%q,%t)", got, present, tc.want, tc.present)
			}
		})
	}
}

// The destination carried by the login flow wins over the shared redirect
// cookie, which is consumed either way. A flow destination that is no longer
// trusted when access is granted falls back to the portal.
func TestGrantAccessPrefersLoginFlowDestination(t *testing.T) {
	trusted := newLoginReturnTrust(t)
	for _, tc := range []struct {
		name         string
		returnURL    string
		bound        bool
		cookie       string
		wantLocation string
	}{
		{name: "flow over cookie", returnURL: "https://app.example.test/flow", cookie: "https://app.example.test/cookie", wantLocation: "https://app.example.test/flow"},
		{name: "flow without cookie", returnURL: "https://app.example.test/flow", wantLocation: "https://app.example.test/flow"},
		{name: "untrusted flow returns to portal", returnURL: "https://evil.example.test/flow", cookie: "https://app.example.test/cookie", wantLocation: "https://login.example.test/auth/portal?redirect_url="},
		{name: "oversized flow returns to portal", returnURL: "https://app.example.test/" + strings.Repeat("a", maxLoginReturnURLLength), cookie: "https://app.example.test/cookie", wantLocation: "https://login.example.test/auth/portal?redirect_url="},
		{name: "untrusted flow without cookie", returnURL: "https://evil.example.test/flow", wantLocation: "https://login.example.test/auth/portal?redirect_url="},
		{name: "bound empty", bound: true, cookie: "https://app.example.test/cookie", wantLocation: "https://login.example.test/auth/portal?redirect_url="},
		{name: "cookie alone", cookie: "https://app.example.test/cookie", wantLocation: "https://app.example.test/cookie"},
		// The same hard bound applies to legacy cookie destinations.
		{name: "long cookie", cookie: "https://app.example.test/" + strings.Repeat("a", 2*maxLoginReturnURLLength), wantLocation: "https://login.example.test/auth/portal"},
		// The cookie is held to the rules the flow destination failed.
		{name: "dot segments in flow and cookie", returnURL: "https://app.example.test/flow/../other", cookie: "https://app.example.test/cookie/%2e%2e/other", wantLocation: "https://login.example.test/auth/portal?redirect_url="},
		{name: "cookie with other scheme", cookie: "ftp://app.example.test/cookie", wantLocation: "https://login.example.test/auth/portal"},
		{name: "cookie without host", cookie: "https:///app.example.test/cookie", wantLocation: "https://login.example.test/auth/portal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := buildGrantAccessPortal([]*redirects.RedirectURIMatchConfig{trusted})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.sessions.Stop)
			r := httptest.NewRequest(http.MethodPost, "https://login.example.test/auth/sandbox/fixture", nil)
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: p.cookie.RefererCookieName, Value: tc.cookie})
			}
			rr := requests.NewRequest()
			rr.Upstream.BasePath = "/auth"
			rr.Upstream.BaseURL = "https://login.example.test"
			rr.Upstream.SessionID = "test-session"
			rr.Response.ReturnURL = tc.returnURL
			rr.Response.ReturnURLBound = tc.bound
			usr := newRefererCleanupUser(t)
			if err := p.keystore.SignToken(nil, nil, usr); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()

			if err := p.grantAccess(t.Context(), w, r, rr, usr); err != nil {
				t.Fatal(err)
			}
			if got := w.Header().Get("Location"); got != tc.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tc.wantLocation)
			}
			if tc.cookie != "" {
				assertSingleRefererDeletion(t, w.Header(), p.cookie, rr.Upstream.BasePath)
			}
		})
	}
}

// A signed-in tab returns straight to the destination its own login URL
// carries: a login page it loads, or a login form left open after the browser
// signed in elsewhere and submitted again. The shared cookie is neither written
// nor read; it is removed only when it holds that destination, which nothing
// else would consume, and another tab's is kept. Without this portal's session,
// or a fresh login, the tab keeps the destination on its portal continuation.
// A rejected destination chooses the portal without consulting the cookie.
func TestHandleHTTPLoginSignedInReturnsToOwnDestination(t *testing.T) {
	trusted := newLoginReturnTrust(t)
	destination := "https://app.example.test/tab?x=one%26two"
	portal := "https://login.example.test/auth/portal"
	for _, tc := range []struct {
		name         string
		method       string
		query        string
		noSession    bool
		wantStatus   int
		wantLocation string
		wantCookie   string
		// cookie is the shared redirect cookie the browser sends, by default
		// another tab's destination.
		cookie string
	}{
		{name: "post with destination", method: http.MethodPost, query: "?redirect_url=" + url.QueryEscape(destination), wantStatus: http.StatusSeeOther, wantLocation: destination},
		{name: "post with destination the cookie holds", method: http.MethodPost, query: "?redirect_url=" + url.QueryEscape(destination), cookie: destination, wantStatus: http.StatusSeeOther, wantLocation: destination, wantCookie: "delete"},
		{name: "fresh post with destination", method: http.MethodPost, query: "?fresh=1&redirect_url=" + url.QueryEscape(destination), wantStatus: http.StatusFound, wantLocation: portal + "?redirect_url=" + url.QueryEscape(destination)},
		{name: "post with untrusted destination", method: http.MethodPost, query: "?redirect_url=" + url.QueryEscape("https://evil.example.test/"), wantStatus: http.StatusSeeOther, wantLocation: portal + "?redirect_url="},
		{name: "post with malformed destination", method: http.MethodPost, query: "?redirect_url=%zz", wantStatus: http.StatusSeeOther, wantLocation: portal + "?redirect_url="},
		{name: "post without destination", method: http.MethodPost, wantStatus: http.StatusFound, wantLocation: portal},
		{name: "post without portal session", method: http.MethodPost, query: "?redirect_url=" + url.QueryEscape(destination), noSession: true, wantStatus: http.StatusFound, wantLocation: portal + "?redirect_url=" + url.QueryEscape(destination)},
		{name: "get with destination", method: http.MethodGet, query: "?redirect_url=" + url.QueryEscape(destination), wantStatus: http.StatusSeeOther, wantLocation: destination},
		{name: "get with destination the cookie holds", method: http.MethodGet, query: "?redirect_url=" + url.QueryEscape(destination), cookie: destination, wantStatus: http.StatusSeeOther, wantLocation: destination, wantCookie: "delete"},
		{name: "get with untrusted destination", method: http.MethodGet, query: "?redirect_url=" + url.QueryEscape("https://evil.example.test/"), wantStatus: http.StatusSeeOther, wantLocation: portal + "?redirect_url="},
		{name: "get with escaping destination", method: http.MethodGet, query: "?redirect_url=" + url.QueryEscape("https://app.example.test/tab/%2e%2e/other"), wantStatus: http.StatusSeeOther, wantLocation: portal + "?redirect_url="},
		{name: "get without portal session", method: http.MethodGet, query: "?redirect_url=" + url.QueryEscape(destination), noSession: true, wantStatus: http.StatusFound, wantLocation: portal + "?redirect_url=" + url.QueryEscape(destination), wantCookie: destination},
		{name: "fresh get with destination", method: http.MethodGet, query: "?fresh=1&redirect_url=" + url.QueryEscape(destination), wantStatus: http.StatusOK, wantCookie: destination},
		{name: "head with destination", method: http.MethodHead, query: "?redirect_url=" + url.QueryEscape(destination), wantStatus: http.StatusSeeOther, wantLocation: destination},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLoginScreenPortal(t, trusted)
			usr := newSignedInUser(t, p, !tc.noSession)
			r := httptest.NewRequest(tc.method, "https://login.example.test/auth/login"+tc.query, nil)
			if tc.cookie == "" {
				tc.cookie = "https://app.example.test/other-tab"
			}
			r.AddCookie(&http.Cookie{Name: p.cookie.RefererCookieName, Value: tc.cookie})
			rr := requests.NewRequest()
			rr.Upstream.BasePath = "/auth"
			rr.Upstream.BaseURL = "https://login.example.test"
			w := httptest.NewRecorder()

			if err := p.handleHTTPLogin(t.Context(), w, r, rr, usr); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.wantStatus || w.Header().Get("Location") != tc.wantLocation {
				t.Fatalf("got HTTP %d to %q, want HTTP %d to %q", w.Code, w.Header().Get("Location"), tc.wantStatus, tc.wantLocation)
			}
			assertRefererCookies(t, w, p, tc.wantCookie)
		})
	}
}

// newSignedInUser returns a signed-in user, holding this portal's session when
// withSession is set.
func newSignedInUser(t *testing.T, p *Portal, withSession bool) *user.User {
	t.Helper()
	usr := newRefererCleanupUser(t)
	usr.Claims.ID = "signed-in-session-0123456789abcdef0123"
	if withSession {
		if err := p.sessions.Add(usr.Claims.ID, usr); err != nil {
			t.Fatal(err)
		}
	}
	return usr
}

// assertRefererCookies checks the redirect cookie the response sets: none when
// want is empty, otherwise exactly one with the value want.
func assertRefererCookies(t *testing.T, w *httptest.ResponseRecorder, p *Portal, want string) {
	t.Helper()
	var cookies []string
	for _, c := range w.Result().Cookies() {
		if c.Name == p.cookie.RefererCookieName {
			cookies = append(cookies, c.Value)
		}
	}
	if want == "" && len(cookies) != 0 || want != "" && (len(cookies) != 1 || cookies[0] != want) {
		t.Fatalf("redirect cookies = %q, want %q", cookies, want)
	}
}

// The login page offers its own destination to the form and the provider links,
// and its script watches for a login completed in another tab, except on a
// fresh login, which has to be completed on that page.
func TestHandleHTTPLoginScreenFlowDestination(t *testing.T) {
	trusted := newLoginReturnTrust(t)
	destination := "https://app.example.test/tab?x=one%26two"
	for _, tc := range []struct {
		name      string
		query     string
		wantForm  string
		wantWatch bool
	}{
		{name: "destination", query: "?redirect_url=" + url.QueryEscape(destination), wantForm: "/auth/login?redirect_url=" + url.QueryEscape(destination), wantWatch: true},
		{name: "untrusted destination", query: "?redirect_url=" + url.QueryEscape("https://evil.example.test/"), wantForm: "/auth/login?redirect_url=", wantWatch: true},
		{name: "no destination", wantForm: "/auth/login?redirect_url=", wantWatch: true},
		{name: "fresh login", query: "?fresh=1", wantForm: "/auth/login?fresh=1&redirect_url="},
		{name: "fresh login with destination", query: "?fresh=1&redirect_url=" + url.QueryEscape(destination), wantForm: "/auth/login?fresh=1&redirect_url=" + url.QueryEscape(destination)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLoginScreenPortal(t, trusted)
			r := httptest.NewRequest(http.MethodGet, "https://login.example.test/auth/login"+tc.query, nil)
			rr := requests.NewRequest()
			rr.Upstream.BasePath = "/auth"
			w := httptest.NewRecorder()

			if err := p.handleHTTPLoginScreen(t.Context(), w, r, rr); err != nil {
				t.Fatal(err)
			}
			page := w.Body.String()
			form := regexpLoginFormAction.FindStringSubmatch(page)
			provider := regexpLoginProviderLink.FindStringSubmatch(page)
			if w.Code != http.StatusOK || form == nil || provider == nil {
				t.Fatalf("login page returned HTTP %d without its form or provider link", w.Code)
			}
			want, err := url.Parse(tc.wantForm)
			if err != nil {
				t.Fatal(err)
			}
			// The form keeps a fresh login fresh; provider links carry only the
			// destination.
			linkQuery := want.Query()
			linkQuery.Del("fresh")
			for _, link := range []struct{ target, path, query string }{
				{form[1], want.Path, want.Query().Encode()},
				{provider[1], "oauth2/upstream", linkQuery.Encode()},
			} {
				got, err := url.Parse(html.UnescapeString(link.target))
				if err != nil {
					t.Fatal(err)
				}
				if got.Path != link.path || got.Query().Encode() != link.query {
					t.Errorf("login page continues at %q, want %q with query %q", link.target, link.path, link.query)
				}
			}
			if watching := strings.Contains(page, `data-whoami="/auth/whoami?probe=login"`); watching != tc.wantWatch {
				t.Errorf("login page watches for a login elsewhere: %t, want %t", watching, tc.wantWatch)
			}
		})
	}
}

// A login URL reached while only the refresh session remains continues that
// session and then returns the tab to its own destination, without the shared
// cookie. The page's sign-in link keeps the destination for a fresh login.
func TestHandleHTTPLoginRefreshContinuesToOwnDestination(t *testing.T) {
	destination := "https://app.example.test/tab?x=one%26two"
	signIn := regexp.MustCompile(`<a href="([^"]*/login\?fresh=1[^"]*)"`)
	next := regexp.MustCompile(`data-action="continue" data-next="([^"]*)"`)
	for _, tc := range []struct {
		name     string
		query    string
		wantNext string
		// cookie is the shared redirect cookie the browser sends, and
		// wantDeleted whether the continue page consumes it.
		cookie      string
		wantDeleted bool
	}{
		{name: "destination", query: "?redirect_url=" + url.QueryEscape(destination), wantNext: destination},
		{name: "destination the cookie holds", query: "?redirect_url=" + url.QueryEscape(destination), wantNext: destination, cookie: destination, wantDeleted: true},
		{name: "destination with another tab's cookie", query: "?redirect_url=" + url.QueryEscape(destination), wantNext: destination, cookie: "https://app.example.test/other-tab"},
		{name: "untrusted destination", query: "?redirect_url=" + url.QueryEscape("https://evil.example.test/")},
		{name: "no destination"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshPortal(t, true, false)
			f.portal.config.TrustedLoginRedirectURIConfigs = []*redirects.RedirectURIMatchConfig{newLoginReturnTrust(t)}
			r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/login"+tc.query, nil)
			r.AddCookie(&http.Cookie{Name: f.portal.cookie.RefreshTokenCookieName, Value: "opaque-refresh"})
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: f.portal.cookie.RefererCookieName, Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			if err := f.portal.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil {
				t.Fatal(err)
			}
			page := w.Body.String()
			gotNext, link := next.FindStringSubmatch(page), signIn.FindStringSubmatch(page)
			if w.Code != http.StatusOK || gotNext == nil || link == nil {
				t.Fatalf("login returned HTTP %d without a session continue page", w.Code)
			}
			wantNext := tc.wantNext
			if wantNext == "" {
				wantNext = "/auth/portal?redirect_url="
			}
			if got := html.UnescapeString(gotNext[1]); got != wantNext {
				t.Errorf("continued session returns to %q, want %q", got, wantNext)
			}
			fresh, err := url.Parse(html.UnescapeString(link[1]))
			if err != nil {
				t.Fatal(err)
			}
			if got := fresh.Query().Get("redirect_url"); !fresh.Query().Has("redirect_url") || got != tc.wantNext {
				t.Errorf("fresh sign-in link carries %q, want %q", got, tc.wantNext)
			}
			var deleted bool
			for _, c := range w.Result().Cookies() {
				if c.Name != f.portal.cookie.RefererCookieName {
					continue
				}
				if c.MaxAge >= 0 || deleted {
					t.Errorf("continue page wrote the shared redirect cookie %q", c.Value)
				}
				deleted = true
			}
			if deleted != tc.wantDeleted {
				t.Errorf("continue page consumed the shared redirect cookie: %t, want %t", deleted, tc.wantDeleted)
			}
		})
	}
}

// iconLoginTestProvider keeps its login icon, as real providers do, so the
// endpoint the portal assigns reaches the login page.
type iconLoginTestProvider struct {
	externalLoginTestProvider
	icon *icons.LoginIcon
}

func (p *iconLoginTestProvider) GetLoginIcon() *icons.LoginIcon { return p.icon }

// OAuth and SAML logins take the tab's destination on their start URL. An HTTP
// login provider owns its query and rejects any on the first request, so its
// link never carries one and its login falls back to the redirect cookie.
func TestLoginPageProviderLinksCarryDestinationOnlyWhereAccepted(t *testing.T) {
	destination := "https://app.example.test/tab?x=one%26two"
	p, err := NewPortal(PortalParameters{
		Config: &PortalConfig{
			Name:                           "provider-links",
			IdentityProviders:              []string{"upstream", "tickets"},
			TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{newLoginReturnTrust(t)},
		},
		Logger: zap.NewNop(),
		IdentityProviders: []idp.IdentityProvider{
			&iconLoginTestProvider{icon: icons.NewLoginIcon("generic")},
			&hookLoginProvider{name: "tickets", realm: "application"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	enabled := map[string]string{}
	for _, authenticator := range p.loginOptions["authenticators"].([]map[string]string) {
		enabled[authenticator["endpoint"]] = authenticator["login_return_url_enabled"]
	}
	if enabled["oauth2/upstream"] != "yes" || enabled["provider/application"] != "" {
		t.Fatalf("login return URL support by endpoint = %q", enabled)
	}

	r := httptest.NewRequest(http.MethodGet, "https://login.example.test/auth/login?redirect_url="+url.QueryEscape(destination), nil)
	w := httptest.NewRecorder()
	if err := p.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	page := w.Body.String()
	links := regexp.MustCompile(`<a href="((?:oauth2|provider)/[^"]*)"`).FindAllStringSubmatch(page, -1)
	got := map[string]string{}
	for _, link := range links {
		target, err := url.Parse(html.UnescapeString(link[1]))
		if err != nil {
			t.Fatal(err)
		}
		got[target.Path] = target.Query().Get("redirect_url")
		if target.Path == "provider/application" && target.RawQuery != "" {
			t.Errorf("HTTP login provider link carries a query: %q", link[1])
		}
	}
	if w.Code != http.StatusOK || len(got) != 2 || got["oauth2/upstream"] != destination {
		t.Fatalf("login page returned HTTP %d with provider destinations %q", w.Code, got)
	}
}

// The waiting login page's probe answers 200 only for a session the portal pages
// accept. A valid access token whose portal session is gone answers 403, so the
// page stops instead of sending the tab where the browser's tokens are deleted.
func TestLoginElsewhereProbeRequiresPortalSession(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	access := responseCookie(t, f.login(t, "cookie"), f.portal.cookie.AccessTokenCookieName)
	if probe := f.request(t, http.MethodGet, "/auth/whoami?probe=login", "", false, access); probe.Code != http.StatusOK {
		t.Fatalf("login probe with a portal session returned HTTP %d", probe.Code)
	}
	if err := f.portal.sessions.Delete(tokenClaims(t, access.Value)["jti"].(string)); err != nil {
		t.Fatal(err)
	}
	probe := f.request(t, http.MethodGet, "/auth/whoami?probe=login", "", false, access)
	if probe.Code != http.StatusForbidden {
		t.Fatalf("login probe without a portal session returned HTTP %d, want 403", probe.Code)
	}
	for _, c := range probe.Result().Cookies() {
		if c.Name == f.portal.cookie.AccessTokenCookieName {
			t.Fatal("login probe deleted the access token")
		}
	}
	if who := f.request(t, http.MethodGet, "/auth/whoami", "", false, access); who.Code != http.StatusOK {
		t.Fatalf("whoami outside the login probe returned HTTP %d", who.Code)
	}
}

// A signed-out tab reaching the portal page keeps its destination in its URL, as
// one reaching the portal root does.
func TestHandleHTTPPortalSignedOutKeepsDestination(t *testing.T) {
	destination := "https://app.example.test/tab?x=one%26two"
	for _, tc := range []struct{ query, want string }{
		{query: "?redirect_url=" + url.QueryEscape(destination), want: "https://login.example.test/auth/login?redirect_url=" + url.QueryEscape(destination)},
		{query: "?redirect_url=" + url.QueryEscape("https://evil.example.test/"), want: "https://login.example.test/auth/login?redirect_url="},
		{query: "?redirect_url=%zz", want: "https://login.example.test/auth/login?redirect_url="},
		{query: "?redirect_url=", want: "https://login.example.test/auth/login?redirect_url="},
		{want: "https://login.example.test/auth/login"},
	} {
		p := newLoginScreenPortal(t, newLoginReturnTrust(t))
		r := httptest.NewRequest(http.MethodGet, "https://login.example.test/auth/portal"+tc.query, nil)
		rr := requests.NewRequest()
		rr.Upstream.BasePath = "/auth"
		rr.Upstream.BaseURL = "https://login.example.test"
		w := httptest.NewRecorder()
		if err := p.handleHTTPPortal(t.Context(), w, r, rr, nil); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusFound || w.Header().Get("Location") != tc.want {
			t.Errorf("portal %q returned HTTP %d to %q, want %q", tc.query, w.Code, w.Header().Get("Location"), tc.want)
		}
	}
}

// A signed-in tab reaching the portal page with its own destination returns
// there, as from the login page, without writing the shared cookie. An explicit
// rejected or empty destination suppresses cookie fallback. Only legacy requests
// without destination context keep the cookie path.
func TestHandleHTTPPortalSignedInReturnsToOwnDestination(t *testing.T) {
	destination := "https://app.example.test/tab?x=one%26two"
	for _, tc := range []struct {
		name         string
		query        string
		cookie       string
		noSession    bool
		wantStatus   int
		wantLocation string
		wantCookie   string
	}{
		{name: "destination", query: "?redirect_url=" + url.QueryEscape(destination), cookie: "https://app.example.test/other-tab", wantStatus: http.StatusSeeOther, wantLocation: destination},
		{name: "destination the cookie holds", query: "?redirect_url=" + url.QueryEscape(destination), cookie: destination, wantStatus: http.StatusSeeOther, wantLocation: destination, wantCookie: "delete"},
		{name: "escaping destination", query: "?redirect_url=" + url.QueryEscape("https://app.example.test/tab/../other"), cookie: "https://app.example.test/other-tab", wantStatus: http.StatusOK},
		{name: "malformed destination", query: "?redirect_url=%zz", cookie: "https://app.example.test/other-tab", wantStatus: http.StatusOK},
		{name: "empty destination", query: "?redirect_url=", cookie: "https://app.example.test/other-tab", wantStatus: http.StatusOK},
		{name: "escaping cookie", cookie: "https://app.example.test/tab/.%2e/other", wantStatus: http.StatusOK, wantCookie: "delete"},
		{name: "without portal session", query: "?redirect_url=" + url.QueryEscape(destination), noSession: true, wantStatus: http.StatusFound, wantLocation: "https://login.example.test/auth/login?redirect_url=" + url.QueryEscape(destination), wantCookie: destination},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLoginScreenPortal(t, newLoginReturnTrust(t))
			usr := newSignedInUser(t, p, !tc.noSession)
			r := httptest.NewRequest(http.MethodGet, "https://login.example.test/auth/portal"+tc.query, nil)
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: p.cookie.RefererCookieName, Value: tc.cookie})
			}
			rr := requests.NewRequest()
			rr.Upstream.BasePath = "/auth"
			rr.Upstream.BaseURL = "https://login.example.test"
			w := httptest.NewRecorder()
			if err := p.handleHTTPPortal(t.Context(), w, r, rr, usr); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.wantStatus || w.Header().Get("Location") != tc.wantLocation {
				t.Fatalf("got HTTP %d to %q, want HTTP %d to %q", w.Code, w.Header().Get("Location"), tc.wantStatus, tc.wantLocation)
			}
			assertRefererCookies(t, w, p, tc.wantCookie)
		})
	}
}
