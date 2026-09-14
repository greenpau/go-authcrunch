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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func replacementLogin(t *testing.T, f *oidcE2EFixture, username, realm, transport, password string, mfa bool, headers http.Header) (oidcE2EResponse, apiauth.AuthResponse) {
	t.Helper()
	req := apiauth.AuthRequest{Username: username, Realm: realm, RefreshTransport: transport}
	start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", headers))
	req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
	req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, password
	response := f.jsonRequest(t, "/login", req, "", headers)
	result := loginIdentityResponse(t, response)
	if mfa {
		if result.Authenticated || result.NextChallenge == "" {
			t.Fatal("password bypassed required MFA")
		}
		req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
		req.ChallengeKind, req.ChallengeResponse = result.NextChallenge, loginIdentityTOTP()
		response = f.jsonRequest(t, "/login", req, "", headers)
		result = loginIdentityResponse(t, response)
	}
	if !result.Authenticated {
		t.Fatal("completed login did not authenticate")
	}
	return response, result
}

func replacementClientWithoutJar(f *oidcE2EFixture) *oidcE2EFixture {
	copy := *f
	client := *f.client
	client.Jar = nil
	copy.client = &client
	return &copy
}

func TestE2EJSONBrowserSessionReplacement(t *testing.T) {
	for _, custom := range []bool{false, true} {
		for _, provider := range []bool{false, true} {
			for _, transition := range []string{"other refresh account", "access-only realm", "same account with MFA"} {
				t.Run(fmt.Sprintf("custom=%t/oidc=%t/%s", custom, provider, transition), func(t *testing.T) {
					var directives []string
					if custom {
						directives = []string{"cookie prefix CUSTOM", "cookie refresh token name CUSTOM_RENEWAL", "cookie oidc session id name CUSTOM_LOGIN"}
					}
					cookies, err := cookieparser.NewCookieConfigFromDirectives(directives)
					if err != nil {
						t.Fatal(err)
					}
					mfa := transition == "same account with MFA"
					f, _, _ := newLoginIdentityE2E(t, true, provider, mfa, "", cookies)
					origin := http.Header{"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}}
					_, first := replacementLogin(t, f, "alice", "local", "", tests.TestPwd1, mfa, origin)
					oldRefresh := loginIdentityCookie(f, cookies.RefreshTokenCookieName)
					oldOIDC := loginIdentityCookie(f, cookies.OIDCSessionIDCookieName)
					if oldRefresh == "" || first.SessionID == "" || (provider && oldOIDC == "") {
						t.Fatal("initial browser family missing")
					}
					// Simulate an old path-scoped cookie that is not sent to /login.
					endpoint, _ := url.Parse(f.issuer + "/api/refresh_token")
					f.client.Jar.SetCookies(endpoint, []*http.Cookie{{Name: cookies.RefreshTokenCookieName, Value: oldRefresh, Path: "/auth/api/refresh_token", Secure: true, HttpOnly: true}})
					username, realm, password := "bob", "local", tests.TestPwd2
					if transition == "access-only realm" {
						realm = "excluded"
					} else if mfa {
						username, password = "alice", tests.TestPwd1
					}
					_, second := replacementLogin(t, f, username, realm, "", password, mfa, origin)
					oldBrowser := replacementClientWithoutJar(f)
					oldHeaders := http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}, "Cookie": {cookies.RefreshTokenCookieName + "=" + oldRefresh}}
					oidcE2EStatus(t, oldBrowser.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", oldHeaders), http.StatusUnauthorized)
					access := loginIdentityCookie(f, cookies.AccessTokenCookieName)
					claims := loginIdentityClaims(t, f, access, username)
					if claims["origin"] != realm {
						t.Fatal("browser retained the previous access identity")
					}
					if realm == "excluded" && second.AccessToken != access {
						t.Fatal("access-only response and browser cookie identify different logins")
					}
					oidcE2EStatus(t, f.request(t, http.MethodGet, "/whoami", nil, nil), http.StatusOK)
					count := 0
					for _, c := range f.client.Jar.Cookies(endpoint) {
						if c.Name == cookies.RefreshTokenCookieName {
							count++
						}
					}
					want := 1
					if realm == "excluded" {
						want = 0
					}
					if count != want {
						t.Fatal("replacement retained an old-path refresh cookie or lost its current cookie")
					}
					if realm != "excluded" {
						if second.SessionID == first.SessionID {
							t.Fatal("replacement reused the old family")
						}
						refreshed := loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}))
						if refreshed.SessionID != second.SessionID {
							t.Fatal("refresh restored the previous identity")
						}
						loginIdentityClaims(t, f, loginIdentityCookie(f, cookies.AccessTokenCookieName), username)
					}
					if provider {
						params := f.authorization("second")
						params.Set("prompt", "none")
						old := oldBrowser.request(t, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, http.Header{"Cookie": {cookies.OIDCSessionIDCookieName + "=" + oldOIDC}})
						target, err := url.Parse(old.header.Get("Location"))
						if err != nil || target.Query().Get("error") != "login_required" {
							t.Fatal("old OIDC browser session survived replacement")
						}
						if realm == "excluded" {
							if loginIdentityCookie(f, cookies.OIDCSessionIDCookieName) != "" {
								t.Fatal("excluded realm retained an OIDC browser session")
							}
						} else {
							code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, nil))
							tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
							info := f.request(t, http.MethodGet, "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
							var body map[string]any
							if info.status != http.StatusOK || json.Unmarshal(info.body, &body) != nil || body["email"] != username+"@example.test" {
								t.Fatal("OIDC session restored the wrong account")
							}
						}
					}
				})
			}
		}
	}
}

func TestE2EIndependentNativeAndAPIKeyLogin(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, true, true, false, "")
	const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	if err := store.Request(operator.AddAPIKey, &requests.Request{User: requests.User{Username: "bob", Email: "bob@example.test"}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "independent login"}}); err != nil {
		t.Fatal("could not provision independent API credential")
	}
	origin := http.Header{"Origin": {f.server.URL}}
	_, browser := replacementLogin(t, f, "alice", "local", "", tests.TestPwd1, false, origin)
	oldRefresh := loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN")
	oldOIDC := loginIdentityCookie(f, "AUTHP_OIDC_SESSION_ID")
	native := replacementClientWithoutJar(f)
	response, body := replacementLogin(t, native, "bob", "local", "body", tests.TestPwd2, false, nil)
	if len(response.header.Values("Set-Cookie")) != 0 || body.RefreshToken == "" {
		t.Fatal("native login modified browser credentials or lost its own family")
	}
	loginIdentityClaims(t, native, body.AccessToken, "bob")
	keyResponse := f.jsonRequest(t, "/login", apiauth.AuthRequest{Realm: "local", APIKey: apiKey}, "", origin)
	key := loginIdentityResponse(t, keyResponse)
	if len(keyResponse.header.Values("Set-Cookie")) != 0 || !key.Authenticated {
		t.Fatal("API-key login changed browser state")
	}
	loginIdentityClaims(t, native, key.AccessToken, "bob")
	if loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") != oldRefresh || loginIdentityCookie(f, "AUTHP_OIDC_SESSION_ID") != oldOIDC {
		t.Fatal("independent credentials replaced the browser account")
	}
	refreshed := loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}))
	if refreshed.SessionID != browser.SessionID {
		t.Fatal("independent login revoked the browser family")
	}
	loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice")
}

func TestE2EBrowserReplacementRejectsForeignOrigin(t *testing.T) {
	for _, flow := range []string{"html", "json"} {
		t.Run(flow, func(t *testing.T) {
			f, _, _ := newLoginIdentityE2E(t, true, false, false, "")
			_, first := replacementLogin(t, f, "alice", "local", "", tests.TestPwd1, false, http.Header{"Origin": {f.server.URL}})
			foreign := http.Header{"Origin": {"https://foreign.example.test"}}
			var response oidcE2EResponse
			if flow == "html" {
				response = f.request(t, http.MethodPost, "/login", url.Values{"username": {"bob"}, "realm": {"excluded"}}, foreign)
			} else {
				response = f.jsonRequest(t, "/login", apiauth.AuthRequest{Username: "bob", Realm: "excluded"}, "", foreign)
			}
			oidcE2EStatus(t, response, http.StatusForbidden)
			refreshed := loginIdentityResponse(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}))
			if refreshed.SessionID != first.SessionID {
				t.Fatal("rejected replacement changed the existing browser family")
			}
		})
	}
}
