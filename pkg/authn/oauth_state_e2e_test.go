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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

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
