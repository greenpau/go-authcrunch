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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	crossparser "github.com/greenpau/go-authcrunch/pkg/authn/cross_device/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
)

func crossDeviceConfig(t *testing.T, config *authn.PortalConfig) {
	t.Helper()
	parsed, err := crossparser.NewCrossDeviceLoginConfigFromDirectives([]string{"enable cross-device login"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(data, &config.CrossDeviceLogin) != nil {
		t.Fatal("config reload failed")
	}
}

func crossDeviceBrowser(f *oidcE2EFixture) *oidcE2EFixture {
	client := *f.client
	client.Jar, _ = cookiejar.New(nil)
	return &oidcE2EFixture{server: f.server, client: &client, issuer: f.issuer, callback: f.callback}
}

func crossDevicePost(t *testing.T, f *oidcE2EFixture, route string, values url.Values) oidcE2EResponse {
	t.Helper()
	if values == nil {
		values = url.Values{}
	}
	return f.request(t, http.MethodPost, "/cross-device/"+route, values, http.Header{"Origin": {crossDeviceOrigin(f)}})
}

func crossDeviceStart(t *testing.T, f *oidcE2EFixture) map[string]string {
	t.Helper()
	return crossDeviceStartDestination(t, f, "")
}

func crossDeviceStartDestination(t *testing.T, f *oidcE2EFixture, destination string) map[string]string {
	t.Helper()
	res := crossDevicePost(t, f, "start?redirect_url="+url.QueryEscape(destination), nil)
	oidcE2EStatus(t, res, http.StatusOK)
	if res.header.Get("Cache-Control") != "no-store" || res.header.Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("interaction can leak via cache/referrer")
	}
	var data map[string]any
	if json.Unmarshal(res.body, &data) != nil {
		t.Fatal("malformed interaction")
	}
	result := map[string]string{}
	for _, key := range []string{"code", "secret", "verification_uri", "display_code", "qr"} {
		value, ok := data[key].(string)
		if !ok || value == "" {
			t.Fatal("missing interaction field")
		}
		result[key] = value
	}
	if strings.Contains(result["verification_uri"], result["secret"]) || !strings.HasPrefix(result["qr"], "data:image/png;base64,") || data["interval"] != float64(2) {
		t.Fatal("invalid QR/polling contract")
	}
	return result
}

func crossDeviceFormToken(t *testing.T, body []byte) string {
	t.Helper()
	found := regexp.MustCompile(`name="csrf" value="([A-Z2-7]+)"`).FindSubmatch(body)
	if len(found) != 2 {
		t.Fatal("missing browser confirmation token")
	}
	return string(found[1])
}

func crossDeviceBegin(t *testing.T, f *oidcE2EFixture, interaction map[string]string) {
	t.Helper()
	res := f.request(t, http.MethodGet, interaction["verification_uri"], nil, nil)
	oidcE2EStatus(t, res, http.StatusOK)
	if !bytes.Contains(res.body, []byte(interaction["display_code"])) {
		t.Fatal("matching code absent")
	}
	csrf := crossDeviceFormToken(t, res.body)
	started := crossDevicePost(t, f, "begin", url.Values{"code": {interaction["code"]}, "csrf": {csrf}})
	oidcE2EStatus(t, started, http.StatusSeeOther)
	if !strings.HasSuffix(started.header.Get("Location"), "/login?fresh=1") {
		t.Fatal("fresh sign-in not requested")
	}
}

func crossDeviceLogin(t *testing.T, f *oidcE2EFixture, mfa bool) oidcE2EResponse {
	t.Helper()
	headers := http.Header{"Origin": {crossDeviceOrigin(f)}}
	start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, headers)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	sandbox := start.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, headers), http.StatusSeeOther)
	if mfa {
		oidcE2EStatus(t, f.request(t, http.MethodGet, "/cross-device/confirm", nil, nil), http.StatusGone)
		oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {loginIdentityTOTP()}}, headers), http.StatusSeeOther)
	}
	finish := f.request(t, http.MethodGet, sandbox, nil, nil)
	oidcE2EStatus(t, finish, http.StatusSeeOther)
	if !strings.HasSuffix(finish.header.Get("Location"), "/cross-device/confirm") {
		t.Fatal("login did not continue to approval")
	}
	confirmation := f.request(t, http.MethodGet, crossDeviceOrigin(f)+finish.header.Get("Location"), nil, nil)
	oidcE2EStatus(t, confirmation, http.StatusOK)
	return confirmation
}

func crossDeviceDecision(t *testing.T, f *oidcE2EFixture, confirmation oidcE2EResponse, decision string) oidcE2EResponse {
	t.Helper()
	return crossDevicePost(t, f, "confirm", url.Values{"csrf": {crossDeviceFormToken(t, confirmation.body)}, "decision": {decision}})
}

func crossDevicePollValues(interaction map[string]string) url.Values {
	return url.Values{"code": {interaction["code"]}, "secret": {interaction["secret"]}}
}

func TestE2ECrossDeviceLogin(t *testing.T) {
	for _, tc := range []struct {
		name, base         string
		refresh, oidc, mfa bool
	}{
		{name: "access", base: "/auth"}, {name: "MFA refresh OIDC", base: "/auth", refresh: true, oidc: true, mfa: true}, {name: "nested", base: "/tenant/security"}, {name: "root"},
		{name: "similar mount prefix", base: "/cross-device-team/auth"},
		{name: "namespace-like mount", base: "/apps/auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := newLoginIdentityConfiguredE2E(t, tc.refresh, tc.oidc, tc.mfa, "", func(config *authn.PortalConfig) { crossDeviceConfig(t, config) })
			f.issuer = crossDeviceOrigin(f) + tc.base
			approver := crossDeviceBrowser(f)
			other := crossDeviceBrowser(f)
			login := f.request(t, http.MethodGet, "/login", nil, nil)
			oidcE2EStatus(t, login, http.StatusOK)
			if !bytes.Contains(login.body, []byte("Sign in on another device")) {
				t.Fatal("enabled login link absent")
			}
			interaction := crossDeviceStart(t, f)
			if !strings.HasPrefix(interaction["verification_uri"], f.issuer+"/cross-device/activate?") {
				t.Fatal("wrong activation mount")
			}
			// The scanned activation capability is insufficient to collect credentials.
			wrong := crossDevicePollValues(interaction)
			wrong.Set("secret", interaction["code"])
			oidcE2EStatus(t, crossDevicePost(t, other, "poll", wrong), http.StatusGone)
			crossDeviceBegin(t, approver, interaction)
			oidcE2EStatus(t, approver.request(t, http.MethodGet, "/cross-device/confirm", nil, nil), http.StatusGone)
			confirmation := crossDeviceLogin(t, approver, tc.mfa)
			pending := crossDevicePost(t, f, "poll", crossDevicePollValues(interaction))
			oidcE2EStatus(t, pending, http.StatusOK)
			if !bytes.Contains(pending.body, []byte(`"pending"`)) || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
				t.Fatal("login bypassed explicit approval")
			}
			oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
			time.Sleep(2 * time.Second)
			redeemed := crossDevicePost(t, f, "poll", crossDevicePollValues(interaction))
			oidcE2EStatus(t, redeemed, http.StatusOK)
			if !bytes.Contains(redeemed.body, []byte(`"approved"`)) || redeemed.header.Get("Authorization") != "" || bytes.Contains(redeemed.body, []byte("access_token")) {
				t.Fatal("redemption missing or exposed bearer material")
			}
			token := loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
			if token == "" || token == loginIdentityCookie(approver, "AUTHP_ACCESS_TOKEN") {
				t.Fatal("requester did not receive independent credentials")
			}
			claims := loginIdentityClaims(t, f, token, "alice")
			methods := "[pwd]"
			if tc.mfa {
				methods = "[pwd otp]"
			}
			if fmt.Sprint(claims["amr"]) != methods || claims["email"] != "alias@example.test" {
				t.Fatal("verified authentication evidence lost")
			}
			oidcE2EStatus(t, f.request(t, http.MethodGet, "/portal", nil, nil), http.StatusOK)
			oidcE2EStatus(t, crossDevicePost(t, f, "poll", crossDevicePollValues(interaction)), http.StatusGone)
			if tc.refresh {
				if loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") == "" || loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") == loginIdentityCookie(approver, "AUTHP_REFRESH_TOKEN") {
					t.Fatal("refresh families not independent")
				}
				oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {crossDeviceOrigin(f)}, "X-Authcrunch-Refresh": {"1"}}), http.StatusOK)
			}
			if tc.oidc {
				code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
				tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
				f.verifyIDToken(t, tokens, "second")
			}
		})
	}
}

func TestE2ECrossDeviceRejections(t *testing.T) {
	for _, scenario := range []string{"denied", "cancelled", "revoked", "logged out", "request context", "concurrent"} {
		t.Run(scenario, func(t *testing.T) {
			f, store, id := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(config *authn.PortalConfig) {
				crossDeviceConfig(t, config)
				if scenario == "request context" {
					config.UserTransformerConfigs = append(config.UserTransformerConfigs, &transformer.Config{Matchers: []string{"regex match iss /cross-device/poll$"}, Actions: []string{"require totp"}})
				}
			})
			approver := crossDeviceBrowser(f)
			interaction := crossDeviceStart(t, f)
			crossDeviceBegin(t, approver, interaction)
			confirmation := crossDeviceLogin(t, approver, false)
			decision := "approve"
			if scenario == "denied" {
				decision = "deny"
			}
			oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, decision), http.StatusOK)
			switch scenario {
			case "cancelled":
				oidcE2EStatus(t, crossDevicePost(t, f, "cancel", crossDevicePollValues(interaction)), http.StatusOK)
			case "revoked":
				if err := store.RevokeUserSessions(t.Context(), id); err != nil {
					t.Fatal(err)
				}
			case "logged out":
				approver.request(t, http.MethodGet, "/logout", nil, nil)
			}
			if scenario == "concurrent" {
				var success atomic.Int32
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() {
						res := crossDevicePost(t, f, "poll", crossDevicePollValues(interaction))
						if res.status == http.StatusOK {
							success.Add(1)
						} else if res.status != http.StatusGone {
							t.Errorf("unexpected redemption status: %d", res.status)
						}
					})
				}
				wg.Wait()
				if success.Load() != 1 {
					t.Fatal("approval redeemed multiple times")
				}
				return
			}
			res := crossDevicePost(t, f, "poll", crossDevicePollValues(interaction))
			want := http.StatusUnauthorized
			if scenario == "denied" || scenario == "cancelled" || scenario == "logged out" {
				want = http.StatusGone
			}
			oidcE2EStatus(t, res, want)
			if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" || loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") != "" {
				t.Fatal("denied transfer issued credentials")
			}
		})
	}
}

func TestE2ECrossDeviceHTTPBoundaries(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(config *authn.PortalConfig) {
		crossDeviceConfig(t, config)
		c, err := cookieparser.NewCookieConfigFromDirectives([]string{"cookie prefix TRANSFER", "cookie cross-device session id name DEVICE_BINDING"})
		if err != nil {
			t.Fatal(err)
		}
		if err := config.ConfigureCookies(c); err != nil {
			t.Fatal(err)
		}
	})
	for _, route := range []string{"start", "begin", "poll", "cancel"} {
		oidcE2EStatus(t, f.request(t, http.MethodGet, "/cross-device/"+route, nil, nil), http.StatusMethodNotAllowed)
		for _, headers := range []http.Header{{}, {"Origin": {"https://attacker.test"}}, {"Origin": {crossDeviceOrigin(f), crossDeviceOrigin(f)}}, {"Origin": {crossDeviceOrigin(f)}, "Sec-Fetch-Site": {"cross-site"}}} {
			oidcE2EStatus(t, f.request(t, http.MethodPost, "/cross-device/"+route, url.Values{}, headers), http.StatusForbidden)
		}
	}
	method := f.request(t, http.MethodPut, "/cross-device/confirm", nil, nil)
	oidcE2EStatus(t, method, http.StatusMethodNotAllowed)
	if method.header.Get("Allow") != "GET, POST" {
		t.Fatal("confirmation response omitted a supported method")
	}
	for _, size := range []int{4096, 4097} {
		body := "padding=" + strings.Repeat("x", size-len("padding="))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+"/cross-device/start", io.NopCloser(strings.NewReader(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = -1 // Exercise the body reader using HTTP chunking.
		req.Header.Set("Origin", crossDeviceOrigin(f))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		response, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		want := http.StatusOK
		if size > 4096 {
			want = http.StatusRequestEntityTooLarge
		}
		if response.StatusCode != want {
			t.Fatalf("streamed form size %d: HTTP %d, want %d", size, response.StatusCode, want)
		}
	}
	interaction := crossDeviceStart(t, f)
	approver := crossDeviceBrowser(f)
	for _, values := range []url.Values{
		{"code": {interaction["code"], interaction["code"]}, "secret": {interaction["secret"]}},
		{"code": {interaction["code"]}, "secret": {interaction["secret"], interaction["secret"]}},
	} {
		oidcE2EStatus(t, crossDevicePost(t, f, "poll", values), http.StatusBadRequest)
	}
	oidcE2EStatus(t, crossDevicePost(t, f, "poll", url.Values{"padding": {strings.Repeat("x", 4097)}}), http.StatusRequestEntityTooLarge)
	oidcE2EStatus(t, f.request(t, http.MethodPost, "/cross-device/poll", crossDevicePollValues(interaction), http.Header{"Origin": {crossDeviceOrigin(f)}, "Content-Type": {"application/json"}}), http.StatusUnsupportedMediaType)
	oidcE2EStatus(t, f.request(t, http.MethodPost, "/cross-device/poll", crossDevicePollValues(interaction), http.Header{"Origin": {crossDeviceOrigin(f)}, "Content-Type": {"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"}}), http.StatusBadRequest)
	for _, path := range []string{"/cross-device/unknown", "/cross-device/api/logout", "/cross-device/oauth2/cross-device", "/cross-device/assets/test.js"} {
		oidcE2EStatus(t, f.request(t, http.MethodGet, path, nil, nil), http.StatusNotFound)
	}
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/cross-device/%61ctivate?code="+interaction["code"], nil, nil), http.StatusNotFound)
	oidcE2EStatus(t, f.request(t, http.MethodGet, interaction["verification_uri"]+"&code="+interaction["code"], nil, nil), http.StatusBadRequest)
	page := approver.request(t, http.MethodGet, interaction["verification_uri"], nil, nil)
	oidcE2EStatus(t, page, http.StatusOK)
	var binding *http.Cookie
	for _, raw := range page.header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(raw)
		if err == nil && c.Name == "DEVICE_BINDING" {
			binding = c
		}
	}
	if binding == nil || !binding.Secure || !binding.HttpOnly || binding.Domain != "" || binding.Path != "/auth" || binding.SameSite != http.SameSiteNoneMode {
		t.Fatal("unsafe approving-browser cookie")
	}
	csrf := crossDeviceFormToken(t, page.body)
	duplicate := crossDeviceBrowser(f)
	values := url.Values{"code": {interaction["code"]}, "csrf": {csrf}}
	duplicateCookies := http.Header{"Origin": {crossDeviceOrigin(f)}, "Cookie": {"DEVICE_BINDING=" + csrf + "; DEVICE_BINDING=" + csrf}}
	oidcE2EStatus(t, duplicate.request(t, http.MethodPost, "/cross-device/begin", values, duplicateCookies), http.StatusForbidden)
	oidcE2EStatus(t, crossDevicePost(t, approver, "begin", url.Values{"code": {interaction["code"]}, "csrf": {"wrong"}}), http.StatusForbidden)
	oidcE2EStatus(t, approver.request(t, http.MethodPost, "/cross-device/begin", url.Values{"code": {interaction["code"]}, "csrf": {csrf}}, http.Header{"Origin": {crossDeviceOrigin(f)}, "Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"}}), http.StatusSeeOther)
	confirmation := crossDeviceLogin(t, approver, false)
	oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
	oidcE2EStatus(t, crossDevicePost(t, f, "poll", crossDevicePollValues(interaction)), http.StatusOK)
	if loginIdentityCookie(f, "TRANSFER_ACCESS_TOKEN") == "" {
		t.Fatal("custom access-cookie config lost")
	}
}

func TestE2ECrossDeviceDisabled(t *testing.T) {
	f, _, _ := newLoginIdentityE2E(t, false, false, false, "")
	res := f.request(t, http.MethodGet, "/login", nil, nil)
	if bytes.Contains(res.body, []byte("Sign in on another device")) {
		t.Fatal("feature visible by default")
	}
	for _, path := range []string{"/cross-device", "/cross-device/start", "/cross-device/activate?code=anything", "/cross-device/confirm"} {
		oidcE2EStatus(t, f.request(t, http.MethodGet, path, nil, nil), http.StatusNotFound)
	}
}

func TestE2ECrossDeviceOAuth(t *testing.T) {
	issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
	portal := newOIDCE2EPortal(t, issuer, "/tenant/auth", "RS512", "discovery", oidcE2ETrustConfig{configurePortal: func(c *authn.PortalConfig) {
		crossDeviceConfig(t, c)
		// An access-only SID claim is not a local refresh family reference.
		c.UserTransformerConfigs = append(c.UserTransformerConfigs, &transformer.Config{Matchers: []string{"regex match sub .*"}, Actions: []string{"add sid external-session as string"}})
	}, identityCookie: "default"})
	client := *portal.client
	client.Jar, _ = cookiejar.New(nil)
	requester := &oidcE2EFixture{server: portal.server, client: &client, issuer: portal.server.URL + portal.base}
	approver := crossDeviceBrowser(requester)
	interaction := crossDeviceStart(t, requester)
	crossDeviceBegin(t, approver, interaction)
	location := portal.server.URL + portal.base + "/oauth2/" + portal.realm
	var complete oidcE2EResponse
	for step := range 3 {
		complete = approver.request(t, http.MethodGet, location, nil, nil)
		if step < 2 {
			oidcE2EStatus(t, complete, http.StatusFound)
		} else {
			oidcE2EStatus(t, complete, http.StatusSeeOther)
		}
		location = complete.header.Get("Location")
	}
	if !strings.HasSuffix(location, "/cross-device/confirm") {
		t.Fatal("verified OAuth login did not reach cross-device approval")
	}
	confirmation := approver.request(t, http.MethodGet, portal.server.URL+location, nil, nil)
	oidcE2EStatus(t, confirmation, http.StatusOK)
	oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
	oidcE2EStatus(t, crossDevicePost(t, requester, "poll", crossDevicePollValues(interaction)), http.StatusOK)
	token := loginIdentityCookie(requester, "oauth_portal_token")
	if token == "" || token == loginIdentityCookie(approver, "oauth_portal_token") {
		t.Fatal("OAuth transfer did not issue independent credentials")
	}
	if status, body := portal.get(t, "/protected", token); status != http.StatusOK || string(body) != "protected-resource" {
		t.Fatal("transferred OAuth credentials failed real gatekeeper")
	}
	// The upstream id_token is a separate credential, never copied to the requester.
	if loginIdentityCookie(requester, "AUTHP_ID_TOKEN") != "" {
		t.Fatal("upstream identity credential crossed devices")
	}
}

func crossDeviceOrigin(f *oidcE2EFixture) string {
	parsed, _ := url.Parse(f.issuer)
	return parsed.Scheme + "://" + parsed.Host
}

func TestE2ECrossDeviceSAML(t *testing.T) {
	saml := newSAMLE2EFixture(t, func(c *authn.PortalConfig) { crossDeviceConfig(t, c) })
	requesterClient := *saml.client
	requesterClient.Jar, _ = cookiejar.New(nil)
	requester := &oidcE2EFixture{server: saml.portal, client: &requesterClient, issuer: saml.portalURL + "/auth"}
	approver := &oidcE2EFixture{server: saml.portal, client: saml.client, issuer: saml.portalURL + "/auth"}
	interaction := crossDeviceStart(t, requester)
	crossDeviceBegin(t, approver, interaction)
	form := saml.begin(t)
	callback := samlE2EPost(t, saml.client, saml.portalURL+"/auth/saml/upstream", form)
	if callback.StatusCode != http.StatusSeeOther || !strings.HasSuffix(callback.Header.Get("Location"), "/cross-device/confirm") {
		t.Fatal("signed SAML callback did not reach approval")
	}
	confirmation := approver.request(t, http.MethodGet, saml.portalURL+callback.Header.Get("Location"), nil, nil)
	oidcE2EStatus(t, confirmation, http.StatusOK)
	oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
	oidcE2EStatus(t, crossDevicePost(t, requester, "poll", crossDevicePollValues(interaction)), http.StatusOK)
	token := loginIdentityCookie(requester, "saml_e2e_token")
	if token == "" || token == loginIdentityCookie(approver, "saml_e2e_token") {
		t.Fatal("SAML transfer did not issue independent credentials")
	}
	oidcE2EStatus(t, requester.request(t, http.MethodGet, "/portal", nil, nil), http.StatusOK)
}

func TestE2ECrossDeviceRefreshLogout(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, true, true, false, "", func(c *authn.PortalConfig) { crossDeviceConfig(t, c) })
	approver := crossDeviceBrowser(f)
	interaction := crossDeviceStart(t, f)
	crossDeviceBegin(t, approver, interaction)
	confirmation := crossDeviceLogin(t, approver, false)
	oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
	headers := http.Header{"Origin": {crossDeviceOrigin(f)}, "X-Authcrunch-Refresh": {"1"}}
	oidcE2EStatus(t, approver.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers), http.StatusOK)
	oidcE2EStatus(t, approver.jsonRequest(t, "/api/logout", map[string]any{}, "", headers), http.StatusOK)
	oidcE2EStatus(t, crossDevicePost(t, f, "poll", crossDevicePollValues(interaction)), http.StatusGone)
	if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("logged-out refresh family authorized a transfer")
	}
}

func TestE2ECrossDeviceExpiredLogin(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(c *authn.PortalConfig) {
		crossDeviceConfig(t, c)
		c.RawCryptoKeyStoreConfig = append(c.RawCryptoKeyStoreConfig, "crypto default token lifetime 2")
	})
	approver := crossDeviceBrowser(f)
	interaction := crossDeviceStart(t, f)
	crossDeviceBegin(t, approver, interaction)
	confirmation := crossDeviceLogin(t, approver, false)
	oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
	time.Sleep(2 * time.Second)
	oidcE2EStatus(t, crossDevicePost(t, f, "poll", crossDevicePollValues(interaction)), http.StatusGone)
	if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("expired login authorized a transfer")
	}
}

func TestE2ECrossDeviceCompletionRollback(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, true, true, false, "", func(config *authn.PortalConfig) {
		crossDeviceConfig(t, config)
		config.OIDCProvider.MaxSessions = 1
		config.RefreshTokens.MaxSessions = 2
	})
	approver := crossDeviceBrowser(f)
	interaction := crossDeviceStart(t, f)
	crossDeviceBegin(t, approver, interaction)
	confirmation := crossDeviceLogin(t, approver, false)
	oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
	// The approver occupies the only OIDC slot. Refuse delivery after access
	// and refresh issuance, then prove the undelivered family was discarded.
	denied := crossDevicePost(t, f, "poll", crossDevicePollValues(interaction))
	oidcE2EStatus(t, denied, http.StatusUnauthorized)
	if denied.header.Get("Authorization") != "" || denied.header.Get("Location") != "" {
		t.Fatal("failed completion delivered credential headers")
	}
	for _, name := range []string{"AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"} {
		if loginIdentityCookie(f, name) != "" {
			t.Fatal("failed completion delivered credentials")
		}
	}
	oidcE2EStatus(t, crossDevicePost(t, f, "poll", crossDevicePollValues(interaction)), http.StatusGone)
	headers := http.Header{"Origin": {crossDeviceOrigin(f)}, "X-Authcrunch-Refresh": {"1"}}
	oidcE2EStatus(t, approver.jsonRequest(t, "/api/logout", map[string]any{}, "", headers), http.StatusOK)
	// Two body-transport logins must fit the two refresh slots. An orphaned
	// undelivered family would deny the second independent session.
	for range 2 {
		browser := crossDeviceBrowser(f)
		_, result := replacementLogin(t, browser, "alice", "local", "body", tests.TestPwd1, false, nil)
		if result.SessionID == "" {
			t.Fatal("completion rollback leaked refresh capacity")
		}
	}
}

func TestE2ECrossDeviceApproverFamilyLifecycle(t *testing.T) {
	for _, scenario := range []string{"logout without access", "replay", "replacement", "rotation"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, _ := newLoginIdentityConfiguredE2E(t, true, false, false, "", func(c *authn.PortalConfig) { crossDeviceConfig(t, c) })
			approver := crossDeviceBrowser(f)
			interaction := crossDeviceStart(t, f)
			crossDeviceBegin(t, approver, interaction)
			confirmation := crossDeviceLogin(t, approver, false)
			oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
			headers := http.Header{"Origin": {crossDeviceOrigin(f)}, "X-Authcrunch-Refresh": {"1"}}
			switch scenario {
			case "logout without access":
				// The refresh logout protocol deliberately does not need an access
				// JWT. A fresh-login screen removes that cookie before logout.
				oidcE2EStatus(t, approver.request(t, http.MethodGet, "/login?fresh=1", nil, nil), http.StatusOK)
				if loginIdentityCookie(approver, "AUTHP_ACCESS_TOKEN") != "" {
					t.Fatal("fresh login retained access")
				}
				oidcE2EStatus(t, approver.jsonRequest(t, "/api/logout", map[string]any{}, "", headers), http.StatusOK)
			case "rotation":
				oidcE2EStatus(t, approver.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers), http.StatusOK)
			case "replay":
				previous := loginIdentityCookie(approver, "AUTHP_REFRESH_TOKEN")
				oidcE2EStatus(t, approver.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", headers), http.StatusOK)
				old := replacementClientWithoutJar(approver)
				replayHeaders := headers.Clone()
				replayHeaders.Set("Cookie", "AUTHP_REFRESH_TOKEN="+previous)
				oidcE2EStatus(t, old.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", replayHeaders), http.StatusUnauthorized)
			case "replacement":
				replacementLogin(t, approver, "bob", "local", "", tests.TestPwd2, false, headers)
			}
			redeemed := crossDevicePost(t, f, "poll", crossDevicePollValues(interaction))
			if scenario == "rotation" {
				oidcE2EStatus(t, redeemed, http.StatusOK)
				if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") == "" {
					t.Fatal("healthy rotated family did not authorize transfer")
				}
				return
			}
			if redeemed.status != http.StatusGone && redeemed.status != http.StatusUnauthorized {
				t.Fatalf("retired approving family authorized transfer: HTTP %d", redeemed.status)
			}
			if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" || loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") != "" {
				t.Fatal("retired approving family delivered credentials")
			}
		})
	}
}

func TestE2ECrossDeviceProviderNamespace(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
			portal := newOIDCE2EPortal(t, issuer, "/tenant/auth", "RS512", "discovery", oidcE2ETrustConfig{
				realm: "cross-device", configurePortal: func(c *authn.PortalConfig) {
					if enabled {
						crossDeviceConfig(t, c)
					}
				},
			})
			token, _ := portal.login(t, http.StatusSeeOther)
			if status, body := portal.get(t, "/protected", token); status != http.StatusOK || string(body) != "protected-resource" {
				t.Fatal("feature route intercepted an OAuth realm")
			}
		})
	}
}

func TestE2ECrossDeviceStaleConfirmation(t *testing.T) {
	first, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(c *authn.PortalConfig) { crossDeviceConfig(t, c) })
	second := crossDeviceBrowser(first)
	approver := crossDeviceBrowser(first)
	firstRequest := crossDeviceStart(t, first)
	crossDeviceBegin(t, approver, firstRequest)
	alice := crossDeviceLogin(t, approver, false)
	if !bytes.Contains(alice.body, []byte("alias@example.test")) {
		t.Fatal("first confirmation lost its account")
	}

	// Another tab in the same approving browser opens a different interaction
	// and logs in as Bob. Its binding cookie replaces the first tab's cookie.
	secondRequest := crossDeviceStart(t, second)
	crossDeviceBegin(t, approver, secondRequest)
	headers := http.Header{"Origin": {crossDeviceOrigin(first)}}
	start := approver.request(t, http.MethodPost, "/login", url.Values{"username": {"bob"}, "realm": {"local"}}, headers)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	sandbox := start.header.Get("Location")
	oidcE2EStatus(t, approver.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd2}}, headers), http.StatusSeeOther)
	completed := approver.request(t, http.MethodGet, sandbox, nil, nil)
	oidcE2EStatus(t, completed, http.StatusSeeOther)
	bob := approver.request(t, http.MethodGet, crossDeviceOrigin(first)+completed.header.Get("Location"), nil, nil)
	oidcE2EStatus(t, bob, http.StatusOK)
	if !bytes.Contains(bob.body, []byte("bob@example.test")) {
		t.Fatal("second confirmation lost its account")
	}

	// Submitting Alice's already-rendered form must not approve Bob's current
	// interaction, even though both tabs now send the same new browser cookie.
	oidcE2EStatus(t, crossDeviceDecision(t, approver, alice, "approve"), http.StatusForbidden)
	for _, pair := range []struct {
		browser *oidcE2EFixture
		request map[string]string
	}{{first, firstRequest}, {second, secondRequest}} {
		pending := crossDevicePost(t, pair.browser, "poll", crossDevicePollValues(pair.request))
		oidcE2EStatus(t, pending, http.StatusOK)
		if !bytes.Contains(pending.body, []byte(`"status":"pending"`)) || loginIdentityCookie(pair.browser, "AUTHP_ACCESS_TOKEN") != "" {
			t.Fatal("stale confirmation approved a transfer")
		}
	}
	oidcE2EStatus(t, crossDeviceDecision(t, approver, bob, "approve"), http.StatusOK)
	time.Sleep(2 * time.Second)
	oidcE2EStatus(t, crossDevicePost(t, second, "poll", crossDevicePollValues(secondRequest)), http.StatusOK)
	loginIdentityClaims(t, second, loginIdentityCookie(second, "AUTHP_ACCESS_TOKEN"), "bob")
	if loginIdentityCookie(first, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("another request received Bob's credentials")
	}
}

func TestE2ECrossDeviceRequesterDestinationIsolation(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, true, true, false, "", func(config *authn.PortalConfig) {
		crossDeviceConfig(t, config)
		trusted, err := redirects.NewRedirectURIMatchConfig("exact", "trusted.example.test", "prefix", "/")
		if err != nil {
			t.Fatal(err)
		}
		config.TrustedLoginRedirectURIConfigs = []*redirects.RedirectURIMatchConfig{trusted}
	})
	destinations := []string{"https://trusted.example.test/first?x=one%26two", "https://trusted.example.test/second?q=" + strings.Repeat("x", 8000), "", "https://evil.example.test/", "https://trusted.example.test/" + strings.Repeat("x", 17000)}
	interactions := make([]map[string]string, len(destinations))
	for i, destination := range destinations {
		interactions[i] = crossDeviceStartDestination(t, f, destination)
	}
	for i := range slices.Backward(interactions) {
		approver := crossDeviceBrowser(f)
		crossDeviceBegin(t, approver, interactions[i])
		confirmation := crossDeviceLogin(t, approver, false)
		oidcE2EStatus(t, crossDeviceDecision(t, approver, confirmation, "approve"), http.StatusOK)
		portal, _ := url.Parse(f.issuer)
		f.client.Jar.SetCookies(portal, []*http.Cookie{{Name: "AUTHP_REDIRECT_URL", Value: "https://trusted.example.test/another-tab", Path: "/"}})
		res := crossDevicePost(t, f, "poll?redirect_url=https%3A%2F%2Ftrusted.example.test%2Fpoll-override", crossDevicePollValues(interactions[i]))
		oidcE2EStatus(t, res, http.StatusOK)
		var data struct{ Status, Next string }
		if err := json.Unmarshal(res.body, &data); err != nil {
			t.Fatal(err)
		}
		want := f.issuer + "/portal?redirect_url="
		if i < 2 {
			want = destinations[i]
		}
		if data.Status != "approved" || data.Next != want {
			t.Fatalf("redemption %d: %#v, want %q", i, data, want)
		}
		if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") == "" {
			t.Fatal("missing authenticated requester")
		}
		oidcE2EStatus(t, crossDevicePost(t, f, "poll", crossDevicePollValues(interactions[i])), http.StatusGone)
	}
}
