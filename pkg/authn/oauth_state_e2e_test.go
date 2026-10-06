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
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
)

func oauthStateRequest(t *testing.T, client *http.Client, location string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("OAuth state request failed")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		t.Fatal("could not read OAuth state response")
	}
	return resp
}

func TestE2EOAuthStateBoundToBrowser(t *testing.T) {
	for _, existingSession := range []bool{false, true} {
		name := "fresh browser"
		if existingSession {
			name = "different existing browser"
		}
		t.Run(name, func(t *testing.T) {
			issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
			portal := newOIDCE2EPortal(t, issuer, "/auth", "RS512", "discovery")
			initiator, recipient := *portal.client, *portal.client
			initiator.Jar, _ = cookiejar.New(nil)
			recipient.Jar, _ = cookiejar.New(nil)
			if existingSession {
				oauthStateRequest(t, &recipient, portal.server.URL+"/auth/login")
			}
			start := oauthStateRequest(t, &initiator, portal.server.URL+"/auth/oauth2/upstream")
			if start.StatusCode != http.StatusFound {
				t.Fatal("could not initiate OAuth flow")
			}
			authorized := oauthStateRequest(t, &initiator, start.Header.Get("Location"))
			if authorized.StatusCode != http.StatusFound {
				t.Fatal("could not authorize at synthetic upstream")
			}
			callback := authorized.Header.Get("Location")
			// Deliver an attacker's valid code+state to an unrelated browser.
			// Upstream signatures, nonce, and PKCE all remain valid.
			stolen := oauthStateRequest(t, &recipient, callback)
			if stolen.StatusCode != http.StatusUnauthorized || stolen.Header.Get("Authorization") != "" {
				t.Fatalf("another browser accepted OAuth callback: HTTP %d", stolen.StatusCode)
			}
			for _, c := range stolen.Cookies() {
				if c.Name == "oauth_portal_token" && c.MaxAge >= 0 {
					t.Fatal("another browser obtained authenticated cookie")
				}
			}
			// A rejected transplant must not destroy the legitimate transaction.
			completed := oauthStateRequest(t, &initiator, callback)
			if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Authorization") == "" {
				t.Fatal("initiating browser could not complete its OAuth transaction")
			}
			replay := oauthStateRequest(t, &initiator, callback)
			if replay.StatusCode != http.StatusUnauthorized || replay.Header.Get("Authorization") != "" {
				t.Fatal("OAuth transaction was accepted twice")
			}
		})
	}
}

func TestE2EExternalLoginReturnURLIsSeparateFromProviderRedirect(t *testing.T) {
	issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
	issuerURL, err := url.Parse(issuer.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", issuerURL.Host, "exact", "/post-login")
	if err != nil {
		t.Fatal(err)
	}
	portal := newOIDCE2EPortal(t, issuer, "/auth", "RS512", "discovery", oidcE2ETrustConfig{loginRedirects: []*redirects.RedirectURIMatchConfig{trusted}})

	for _, tc := range []struct {
		name, returnURL, wantFinal string
		wantReturnCookie           bool
	}{
		{
			name:             "trusted return URL is used after authentication",
			returnURL:        issuer.server.URL + "/post-login",
			wantFinal:        issuer.server.URL + "/post-login",
			wantReturnCookie: true,
		},
		{
			name:      "untrusted return URL is rejected",
			returnURL: "https://evil.example.test/post-login",
			wantFinal: portal.server.URL + "/auth/portal",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := *portal.client
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			startURL := portal.server.URL + "/auth/oauth2/upstream?redirect_url=" + url.QueryEscape(tc.returnURL)
			start := oauthStateRequest(t, &client, startURL)
			if start.StatusCode != http.StatusFound {
				t.Fatalf("external login returned HTTP %d", start.StatusCode)
			}
			authorizationURL, err := url.Parse(start.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if authorizationURL.Scheme != issuerURL.Scheme || authorizationURL.Host != issuerURL.Host || authorizationURL.Path != "/authorize" {
				t.Fatalf("external login redirected to %q, want the configured provider authorization endpoint", authorizationURL.String())
			}
			var gotReturnCookie bool
			for _, responseCookie := range start.Cookies() {
				if responseCookie.Name == "AUTHP_REDIRECT_URL" {
					gotReturnCookie = true
					if responseCookie.Value != tc.returnURL || responseCookie.Path != "/auth" {
						t.Fatalf("return cookie = %#v, want value %q and path /auth", responseCookie, tc.returnURL)
					}
				}
			}
			if gotReturnCookie != tc.wantReturnCookie {
				t.Fatalf("return cookie present = %t, want %t", gotReturnCookie, tc.wantReturnCookie)
			}

			authorized := oauthStateRequest(t, &client, start.Header.Get("Location"))
			if authorized.StatusCode != http.StatusFound {
				t.Fatalf("synthetic provider returned HTTP %d", authorized.StatusCode)
			}
			completed := oauthStateRequest(t, &client, authorized.Header.Get("Location"))
			if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != tc.wantFinal {
				t.Fatalf("completed login returned HTTP %d to %q, want HTTP %d to %q", completed.StatusCode, completed.Header.Get("Location"), http.StatusSeeOther, tc.wantFinal)
			}
			if tc.wantReturnCookie {
				destination := oauthStateRequest(t, &client, completed.Header.Get("Location"))
				if destination.StatusCode != http.StatusOK {
					t.Fatalf("accepted post-login destination returned HTTP %d", destination.StatusCode)
				}
			}
		})
	}
}

var providerLoginLink = regexp.MustCompile(`<a href="(oauth2/upstream[^"]*)"`)

// startOAuthTab follows a tab from the portal root to its login page, starts the
// login through the provider link that page offers, and returns the callback.
func startOAuthTab(t *testing.T, portal *oidcE2EPortal, client *http.Client, returnURL string) string {
	t.Helper()
	next, err := url.Parse(portal.server.URL + "/auth/?redirect_url=" + url.QueryEscape(returnURL))
	if err != nil {
		t.Fatal(err)
	}
	for next.Path != "/auth/login" {
		resp := oauthStateRequest(t, client, next.String())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("portal root returned HTTP %d", resp.StatusCode)
		}
		if next, err = next.Parse(resp.Header.Get("Location")); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := client.Get(next.String())
	if err != nil {
		t.Fatal("login page request failed")
	}
	page, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login page returned HTTP %d", resp.StatusCode)
	}
	m := providerLoginLink.FindSubmatch(page)
	if m == nil {
		t.Fatal("login page offers no provider link")
	}
	start, err := next.Parse(html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatal(err)
	}
	started := oauthStateRequest(t, client, start.String())
	if started.StatusCode != http.StatusFound {
		t.Fatalf("external login returned HTTP %d", started.StatusCode)
	}
	authorized := oauthStateRequest(t, client, started.Header.Get("Location"))
	if authorized.StatusCode != http.StatusFound {
		t.Fatalf("synthetic provider returned HTTP %d", authorized.StatusCode)
	}
	return authorized.Header.Get("Location")
}

// loginElsewhereProbe asks whoami as a waiting login page does.
func loginElsewhereProbe(t *testing.T, client *http.Client, location string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("login probe request failed")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		t.Fatal("could not read login probe response")
	}
	return resp
}

func newPerTabOAuthPortal(t *testing.T, admitted bool) (*oidcE2EPortal, *http.Client) {
	t.Helper()
	issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
	issuerURL, err := url.Parse(issuer.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", issuerURL.Host, "prefix", "/post-login/")
	if err != nil {
		t.Fatal(err)
	}
	trust := oidcE2ETrustConfig{loginRedirects: []*redirects.RedirectURIMatchConfig{trusted}}
	if admitted {
		// The portal admits the provider's users, so a tab still on its login
		// page can see from whoami that the browser is signed in.
		trust.configurePortal = func(c *authn.PortalConfig) {
			c.AccessListConfigs = []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}
		}
	}
	portal := newOIDCE2EPortal(t, issuer, "/auth", "RS512", "discovery", trust)
	client := *portal.client
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return portal, &client
}

// Two tabs of one browser start OAuth logins from their own login pages, the
// way a user does after several tabs hit the login redirect at once. However
// their callbacks interleave, each must return to its own page: the shared
// redirect cookie holds only the destination of the tab that arrived last.
func TestE2EExternalLoginReturnsEachTabToItsOwnPage(t *testing.T) {
	portal, client := newPerTabOAuthPortal(t, true)
	first := portal.issuer.server.URL + "/post-login/first"
	second := portal.issuer.server.URL + "/post-login/second?view=one%26two"
	firstCallback := startOAuthTab(t, portal, client, first)
	secondCallback := startOAuthTab(t, portal, client, second)
	// The provider chooses the callback URL, so a destination it carries does
	// not replace the one its login started with.
	firstCallback += "&redirect_url=" + url.QueryEscape(portal.issuer.server.URL+"/post-login/chosen-by-callback")

	for _, tab := range []struct{ callback, want string }{{secondCallback, second}, {firstCallback, first}} {
		completed := oauthStateRequest(t, client, tab.callback)
		if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != tab.want {
			t.Errorf("tab for %q completed with HTTP %d to %q", tab.want, completed.StatusCode, completed.Header.Get("Location"))
		}
	}
	// A tab still on its login page asks whoami whether the browser is signed in.
	if probe := loginElsewhereProbe(t, client, portal.server.URL+"/auth/whoami?probe=login"); probe.StatusCode != http.StatusOK {
		t.Errorf("login probe after an OAuth login returned HTTP %d, want 200", probe.StatusCode)
	}
}

// A portal need not admit every account its gatekeepers accept. A login page
// waiting in another tab must then neither leave for the portal nor, by asking,
// delete the access token the browser's other tabs use. Tokens that are invalid
// rather than not admitted are still removed.
func TestE2ELoginElsewhereProbeKeepsTokenThePortalDoesNotAdmit(t *testing.T) {
	portal, client := newPerTabOAuthPortal(t, false)
	destination := portal.issuer.server.URL + "/post-login/app"
	completed := oauthStateRequest(t, client, startOAuthTab(t, portal, client, destination))
	if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != destination {
		t.Fatalf("OAuth login completed with HTTP %d", completed.StatusCode)
	}
	// The fixture's keystore names the access token.
	const accessName = "oauth_portal_token"
	issued := completed.Cookies()
	i := slices.IndexFunc(issued, func(c *http.Cookie) bool { return c.Name == accessName && c.Value != "" })
	if i < 0 {
		t.Fatal("OAuth login issued no access token cookie")
	}
	token := issued[i].Value
	deletes := func(resp *http.Response) bool {
		for _, c := range resp.Cookies() {
			if c.Name == accessName && c.MaxAge < 0 {
				return true
			}
		}
		return false
	}

	for range 2 {
		probe := loginElsewhereProbe(t, client, portal.server.URL+"/auth/whoami?probe=login")
		if probe.StatusCode != http.StatusForbidden || deletes(probe) {
			t.Fatalf("login probe for an account the portal does not admit returned HTTP %d, deleting the token: %t", probe.StatusCode, deletes(probe))
		}
	}
	if whoami := loginElsewhereProbe(t, client, portal.server.URL+"/auth/whoami"); whoami.StatusCode != http.StatusUnauthorized || !deletes(whoami) {
		t.Fatalf("whoami outside the login probe returned HTTP %d, deleting the token: %t", whoami.StatusCode, deletes(whoami))
	}

	invalid := *client
	var err error
	invalid.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	portalURL, err := url.Parse(portal.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	forged := token[:strings.LastIndex(token, ".")+1] + "AAAA" + token[strings.LastIndex(token, ".")+5:]
	invalid.Jar.SetCookies(portalURL, []*http.Cookie{{Name: accessName, Value: forged, Path: "/"}})
	if probe := loginElsewhereProbe(t, &invalid, portal.server.URL+"/auth/whoami?probe=login"); probe.StatusCode != http.StatusUnauthorized || !deletes(probe) {
		t.Fatalf("login probe with an invalid token returned HTTP %d, deleting it: %t", probe.StatusCode, deletes(probe))
	}
}
