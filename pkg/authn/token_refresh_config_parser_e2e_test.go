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
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
)

func (f *jwksE2EPortal) browserRefreshRequest(t *testing.T, endpoint string, body any, status int, cookies ...*http.Cookie) (*apiauth.AuthResponse, []*http.Cookie) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal("could not encode browser request")
	}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+f.base+endpoint, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", f.server.URL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Authcrunch-Refresh", "1")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal("browser credential request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("browser %s HTTP %d, want %d", endpoint, response.StatusCode, status)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("browser credential response allowed caching")
	}
	var result apiauth.AuthResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		t.Fatal("invalid browser credential response")
	}
	if result.AccessToken != "" || result.RefreshToken != "" || (status != http.StatusOK && result.Authenticated) {
		t.Fatal("browser response disclosed credentials or authenticated a failed request")
	}
	return &result, response.Cookies()
}

func refreshDirectiveCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name && c.MaxAge > 0 && c.Value != "" {
			return c
		}
	}
	t.Fatal("missing active credential cookie")
	return nil
}

func TestE2ETokenRefreshDirectiveBrowser(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name, base, cookieName string
		settings               []string
	}{
		{"root", "", "ROOT_REFRESH_TOKEN", nil},
		{"nested", "/tenant/auth", "TENANT_REFRESH_TOKEN", []string{"body transport disabled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := append([]string{"cookie name " + tc.cookieName, "access lifetime 45", "idle timeout 90", "absolute timeout 240"}, tc.settings...)
			f := newJWKSE2EPortalWithRefresh(t, db, tc.base, nil, settings)
			// Neither omitted nor explicitly disabled body transport permits
			// opting into native credentials at login or at the refresh route.
			f.postCredentials(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local", RefreshTransport: "body"}, 400)
			begin, _ := f.browserRefreshRequest(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local"}, 200)
			login, cookies := f.browserRefreshRequest(t, "/login", apiauth.AuthRequest{
				Username: "keyadmin", Realm: "local", SandboxID: begin.SandboxID, SandboxSecret: begin.SandboxSecret,
				ChallengeKind: "password", ChallengeResponse: tests.TestPwd1,
			}, 200)
			if !login.Authenticated || login.SessionID == "" {
				t.Fatal("browser login did not establish a refresh session")
			}
			refresh := refreshDirectiveCookie(t, cookies, tc.cookieName)
			mount := tc.base
			if mount == "" {
				mount = "/"
			}
			if refresh.Path != mount || refresh.Domain != "" || !refresh.Secure || !refresh.HttpOnly || refresh.SameSite != http.SameSiteLaxMode || refresh.Expires.Unix() != login.RefreshExpiresAt {
				t.Fatal("configured refresh cookie policy was not enforced")
			}
			f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": refresh.Value}, 403)
			rotated, cookies := f.browserRefreshRequest(t, "/api/refresh_token", struct{}{}, 200, refresh)
			next := refreshDirectiveCookie(t, cookies, tc.cookieName)
			if next.Value == refresh.Value || rotated.SessionID != login.SessionID || rotated.SessionExpiresAt != login.SessionExpiresAt {
				t.Fatal("browser rotation changed the session or retained its credential")
			}
			_, publicJSON := f.request(t, "GET", e2eJWKSPath, "", 200)
			public := decodeE2EJWKS(t, publicJSON, 1)
			// Locate the access cookie independently of its configurable name.
			accessFound := false
			for _, c := range cookies {
				if c.Name == tc.cookieName || c.MaxAge <= 0 || c.Expires.Unix() != rotated.AccessExpiresAt {
					continue
				}
				claims := verifyE2EJWKSToken(t, public, c.Value, "keyadmin").Claims.(jwtlib.MapClaims)
				if claims["iss"] != f.server.URL+tc.base || claims["exp"].(float64)-claims["iat"].(float64) != 45 || rotated.RefreshExpiresAt-int64(claims["iat"].(float64)) != 90 {
					t.Fatal("configured issuer or lifetimes were not used for browser rotation")
				}
				f.request(t, "GET", "/whoami", c.Value, 200)
				accessFound = true
			}
			if !accessFound {
				t.Fatal("browser rotation did not deliver a signed access cookie")
			}
			f.browserRefreshRequest(t, "/api/refresh_token", struct{}{}, 401, refresh)
			f.browserRefreshRequest(t, "/api/refresh_token", struct{}{}, 401, next)
		})
	}
}

func TestE2ETokenRefreshDirectiveLimits(t *testing.T) {
	f := newJWKSE2EPortalWithRefresh(t, newJWKSE2EDatabase(t), "/auth", nil, []string{
		"enabled", "body transport enabled", "cookie name NATIVE_REFRESH_TOKEN",
		"access lifetime 45", "idle timeout 90", "absolute timeout 240", "max sessions 1", "max rotations 1",
	})
	start := time.Now().Unix()
	begin := f.postCredentials(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local", RefreshTransport: "body"}, 200)
	login := f.postCredentials(t, "/login", apiauth.AuthRequest{
		Username: "keyadmin", Realm: "local", RefreshTransport: "body", SandboxID: begin.SandboxID, SandboxSecret: begin.SandboxSecret,
		ChallengeKind: "password", ChallengeResponse: tests.TestPwd1,
	}, 200)
	if !login.Authenticated || login.RefreshToken == "" || login.RefreshTokenName != "NATIVE_REFRESH_TOKEN" || login.SessionID == "" {
		t.Fatal("native login did not honor refresh configuration")
	}
	if login.SessionExpiresAt < start+240 || login.SessionExpiresAt > time.Now().Unix()+240 {
		t.Fatal("native login did not honor the absolute timeout")
	}
	_, publicJSON := f.request(t, "GET", e2eJWKSPath, "", 200)
	public := decodeE2EJWKS(t, publicJSON, 1)
	claims := verifyE2EJWKSToken(t, public, login.AccessToken, "keyadmin").Claims.(jwtlib.MapClaims)
	if claims["iss"] != f.server.URL+f.base || claims["exp"].(float64)-claims["iat"].(float64) != 45 || login.RefreshExpiresAt-int64(claims["iat"].(float64)) != 90 || login.AccessExpiresAt != int64(claims["exp"].(float64)) {
		t.Fatal("native login did not honor the issuer or lifetimes")
	}
	// An independent login exceeds capacity but must not revoke the first one.
	second := f.postCredentials(t, "/login", apiauth.AuthRequest{Username: "keymember", Realm: "local", RefreshTransport: "body"}, 200)
	f.postCredentials(t, "/login", apiauth.AuthRequest{
		Username: "keymember", Realm: "local", RefreshTransport: "body", SandboxID: second.SandboxID, SandboxSecret: second.SandboxSecret,
		ChallengeKind: "password", ChallengeResponse: tests.TestPwd1,
	}, 503)
	rotated := f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, 200)
	if rotated.RefreshToken == "" || rotated.RefreshToken == login.RefreshToken || rotated.SessionID != login.SessionID || rotated.SessionExpiresAt != login.SessionExpiresAt {
		t.Fatal("capacity rejection affected the existing session")
	}
	verifyE2EJWKSToken(t, public, rotated.AccessToken, "keyadmin")
	f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": rotated.RefreshToken}, 401)
}

func TestE2ETokenRefreshDirectiveDisabled(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name       string
		statements []string
	}{
		{"absent", nil},
		{"disabled", []string{"disabled", "body transport enabled", "access lifetime 45"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWKSE2EPortalWithRefresh(t, db, "/auth", nil, tc.statements, "crypto default token lifetime 600")
			access := f.login(t, "keyadmin")
			_, publicJSON := f.request(t, "GET", e2eJWKSPath, "", 200)
			claims := verifyE2EJWKSToken(t, decodeE2EJWKS(t, publicJSON, 1), access, "keyadmin").Claims.(jwtlib.MapClaims)
			if claims["exp"].(float64)-claims["iat"].(float64) != 600 || claims["sid"] != nil {
				t.Fatal("disabled refresh changed ordinary access issuance")
			}
			f.postCredentials(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local", RefreshTransport: "body"}, 400)
			f.postCredentials(t, "/api/refresh_token", struct{}{}, 404)
			f.postCredentials(t, "/api/logout", struct{}{}, 404)
		})
	}
}

// A real cookie jar catches name/path mistakes hidden by selecting a response
// cookie manually, especially when active and legacy cookies share a name.
func TestE2ETokenRefreshCookieLifecycle(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name, base, want, override string
		directives                 []string
	}{
		{name: "default root", want: "AUTHP_REFRESH_TOKEN"},
		{name: "default nested", base: "/auth", want: "AUTHP_REFRESH_TOKEN"},
		{name: "custom prefix", base: "/tenant/auth", directives: []string{"cookie prefix TENANT"}, want: "TENANT_REFRESH_TOKEN"},
		{name: "explicit cookie name", base: "/auth", directives: []string{"cookie prefix TENANT", "cookie refresh token name LOGIN_REFRESH"}, want: "LOGIN_REFRESH"},
		{name: "directive override", base: "/auth", directives: []string{"cookie prefix TENANT", "cookie refresh token name COOKIE_REFRESH"}, override: "DIRECTIVE_REFRESH", want: "DIRECTIVE_REFRESH"},
		{name: "independent security attributes", base: "/auth", directives: []string{"cookie prefix CUSTOM", "cookie insecure enabled", "cookie same site none", "cookie path /", "cookie lifetime 3600"}, want: "CUSTOM_REFRESH_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := []string{"access lifetime 45", "idle timeout 90", "absolute timeout 240"}
			if tc.override != "" {
				settings = append(settings, "cookie name "+tc.override)
			}
			cookiesConfig, err := cookieparser.NewCookieConfigFromDirectives(tc.directives)
			if err != nil {
				t.Fatal(err)
			}
			f := newJWKSE2EPortalWithCookies(t, db, tc.base, nil, cookiesConfig, settings)
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			f.client.Jar = jar
			loginURL, err := url.Parse(f.server.URL + tc.base + "/login")
			if err != nil {
				t.Fatal(err)
			}
			refreshURL, err := url.Parse(f.server.URL + tc.base + "/api/refresh_token")
			if err != nil {
				t.Fatal(err)
			}
			// Existing route-scoped JWT cookies must be removed during login
			// without deleting the new mount-scoped opaque credential.
			jar.SetCookies(refreshURL, []*http.Cookie{{Name: tc.want, Value: "legacy-credential", Path: tc.base + "/api/refresh_token", Secure: true}})
			begin, _ := f.browserRefreshRequest(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local"}, 200)
			login, cookies := f.browserRefreshRequest(t, "/login", apiauth.AuthRequest{
				Username: "keyadmin", Realm: "local", SandboxID: begin.SandboxID, SandboxSecret: begin.SandboxSecret,
				ChallengeKind: "password", ChallengeResponse: tests.TestPwd1,
			}, 200)
			if !login.Authenticated || login.SessionID == "" {
				t.Fatal("browser login did not establish a refresh session")
			}
			credential := refreshDirectiveCookie(t, cookies, tc.want)
			mount := tc.base
			if mount == "" {
				mount = "/"
			}
			if credential.Path != mount || credential.Domain != "" || !credential.Secure || !credential.HttpOnly || credential.SameSite != http.SameSiteLaxMode || credential.MaxAge > 90 {
				t.Fatal("refresh cookie did not preserve its security, path, or lifetime policy")
			}
			for _, target := range []*url.URL{loginURL, refreshURL} {
				count := 0
				for _, c := range jar.Cookies(target) {
					if c.Name == tc.want {
						count++
						if c.Value != credential.Value {
							t.Fatal("legacy or stale cookie survived login")
						}
					}
				}
				if count != 1 {
					t.Fatal("browser retained duplicate cookies or lost the active credential")
				}
			}
			rotated, cookies := f.browserRefreshRequest(t, "/api/refresh_token", struct{}{}, 200)
			next := refreshDirectiveCookie(t, cookies, tc.want)
			if next.Value == credential.Value || rotated.SessionID != login.SessionID {
				t.Fatal("cookie-jar refresh did not rotate the same session")
			}
			f.browserRefreshRequest(t, "/api/logout", struct{}{}, 200)
			for _, target := range []*url.URL{loginURL, refreshURL} {
				for _, c := range jar.Cookies(target) {
					if c.Name == tc.want {
						t.Fatal("logout failed to delete the configured refresh cookie")
					}
				}
			}
			// A revoked credential stays unusable even outside the browser jar.
			f.client.Jar = nil
			f.browserRefreshRequest(t, "/api/refresh_token", struct{}{}, 401, next)
		})
	}
}
