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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	stateparser "github.com/greenpau/go-authcrunch/pkg/state/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

func persistentTestConfig(t *testing.T) *state.Config {
	t.Helper()
	c, err := stateparser.NewStateConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"directory", filepath.Join(t.TempDir(), "private state")})})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func restartDirectOAuth(t *testing.T, f *directOAuthFixture) {
	t.Helper()
	if err := f.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	var cfg authcrunch.Config
	if err := json.Unmarshal(f.config, &cfg); err != nil {
		t.Fatal(err)
	}
	var err error
	f.runtime, err = authcrunch.NewServer(&cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	clear(f.gatekeepers)
	for _, policy := range cfg.AuthorizationPolicies {
		f.gatekeepers[policy.Name], err = f.runtime.GetGatekeeperByName(policy.Name)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestE2EServerPersistentOAuthWithoutPortal(t *testing.T) {
	stateConfig := persistentTestConfig(t)
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) { c.State = stateConfig })
	callback := f.callback(t, f.client, "/private?preserved=yes")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
	exchanges := f.exchanges.Load()
	// Keep a pending login in a different browser. Restart may retain completed
	// sessions but must not turn unfinished upstream authentication into a session.
	pending := *f.client
	pending.Jar, _ = cookiejar.New(nil)
	unfinished := f.callback(t, &pending, "/private")
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
	if f.exchanges.Load() != exchanges {
		t.Fatal("restored session triggered an upstream exchange")
	}
	directOAuthStatus(t, f.request(t, &pending, "GET", unfinished, nil), 400)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/admin", nil), 403)
	// Verify serialization of the normalized running configuration also restores.
	var err error
	f.config, err = json.Marshal(f.runtime.GetConfig())
	if err != nil {
		t.Fatal(err)
	}
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
	u, _ := url.Parse(f.server.URL)
	cookies := f.client.Jar.Cookies(u)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/_authcrunch/oauth2/primary/logout", http.Header{"Origin": {f.server.URL}}), 204)
	restartDirectOAuth(t, f)
	f.client.Jar.SetCookies(u, cookies)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 401)
}

func TestE2EServerPersistentPortalRefreshAndOIDC(t *testing.T) {
	stateConfig := persistentTestConfig(t)
	f := newServerCompositionFixture(t, false, func(c *authcrunch.Config) { c.State = stateConfig })
	var saved authcrunch.Config
	if err := saved.LoadFromJSONFile(f.stateFile); err != nil {
		t.Fatal(err)
	}
	app, err := saved.GetOAuthApplication("website")
	if err != nil {
		t.Fatal(err)
	}
	client := app.Client
	f.login(t, "local", "alice")
	code := compositionCode(t, f.authorize(t, client))
	response := f.exchange(t, client, code, client.ClientSecret)
	compositionStatus(t, response, 200)
	tokens := compositionJSON(t, response)
	f.verify(t, tokens["id_token"].(string), "/oidc/jwks")
	oidcAccess := tokens["access_token"].(string)
	// Native refresh keeps the same browser OIDC session and has its own family.
	native := f.native(t, "alice")
	profileHeaders := http.Header{"Origin": {f.origin}, "Content-Type": {"application/json"}}
	key, _ := json.Marshal(map[string]string{"kind": "add_user_api_key", "title": "PersistentKey", "description": "restart regression", "content": strings.Repeat("Abcd1234", 8)})
	compositionStatus(t, f.request(t, "POST", "/api/profile", string(key), profileHeaders), 200)
	compositionStatus(t, f.request(t, "GET", "/portal", "", nil), 200)
	f.replace(t, false, "")
	compositionStatus(t, f.request(t, "GET", "/portal", "", nil), 200)
	compositionStatus(t, f.request(t, "POST", "/api/profile", `{"kind":"fetch_user_api_keys"}`, profileHeaders), 200)
	compositionStatus(t, f.request(t, "GET", f.origin+"/protected", "", http.Header{"Authorization": {"Bearer " + native.AccessToken}}), 204)
	compositionStatus(t, f.request(t, "GET", "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + oidcAccess}}), 200)
	_ = compositionCode(t, f.authorize(t, client))
	// A spent authorization code must still revoke the previously issued token.
	compositionStatus(t, f.exchange(t, client, code, client.ClientSecret), 400)
	f.replace(t, false, "")
	compositionStatus(t, f.request(t, "GET", "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + oidcAccess}}), 401)
	jar := f.client.Jar
	f.client.Jar = nil
	defer func() { f.client.Jar = jar }()
	refresh := func(token string) compositionResponse {
		raw, _ := json.Marshal(map[string]string{"refresh_token": token})
		return f.request(t, "POST", "/api/refresh_token", string(raw), http.Header{"Content-Type": {"application/json"}})
	}
	rotated := refresh(native.RefreshToken)
	compositionStatus(t, rotated, 200)
	next := compositionJSON(t, rotated)["refresh_token"].(string)
	f.replace(t, false, "")
	compositionStatus(t, refresh(native.RefreshToken), 401)
	f.replace(t, false, "")
	compositionStatus(t, refresh(next), 401)
}

func TestE2EServerPersistentOAuthConfigurationEpoch(t *testing.T) {
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) { c.State = persistentTestConfig(t) })
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	original := append([]byte(nil), f.config...)
	var cfg authcrunch.Config
	if err := json.Unmarshal(original, &cfg); err != nil {
		t.Fatal(err)
	}
	for i, policy := range cfg.AuthorizationPolicies {
		if policy.Name == "primary" {
			cfg.AuthorizationPolicies = append(cfg.AuthorizationPolicies[:i], cfg.AuthorizationPolicies[i+1:]...)
			break
		}
	}
	var err error
	f.config, err = json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	restartDirectOAuth(t, f)
	f.config = original
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 401)
}

func TestE2EServerPersistentOAuthInterruptedCommit(t *testing.T) {
	stateConfig := persistentTestConfig(t)
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) { c.State = stateConfig })
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 200)
	oldBrowser := *f.client
	oldBrowser.Jar, _ = cookiejar.New(nil)
	origin, _ := url.Parse(f.server.URL)
	oldBrowser.Jar.SetCookies(origin, f.client.Jar.Cookies(origin))
	if err := f.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	// Reproduce the durable boundary of an interrupted revocation: its intent
	// marker reached disk, but the previously valid session snapshot remains.
	hash := sha256.Sum256([]byte("oauth-sessions/primary"))
	marker := filepath.Join(stateConfig.Directory, fmt.Sprintf("%x.state.pending", hash))
	if err := os.WriteFile(marker, []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, &oldBrowser, "POST", "/private", nil), 401)
	// Recovery must permit a fresh authentication without reviving the
	// ambiguous old session, including after another ordinary restart.
	callback = f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 200)
	restartDirectOAuth(t, f)
	directOAuthStatus(t, f.request(t, &oldBrowser, "POST", "/private", nil), 401)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), 200)
}

func TestE2EServerPersistentOIDCRefresh(t *testing.T) {
	stateConfig := persistentTestConfig(t)
	f := newServerCompositionFixture(t, false, func(c *authcrunch.Config) {
		c.State = stateConfig
		c.AuthenticationPortals[0].OIDCProvider.Clients[0].Scopes = []string{"openid", "profile", "email", "offline_access"}
	})
	client := f.replace(t, false, "")
	f.login(t, "local", "alice")
	digest := sha256.Sum256([]byte(compositionVerifier))
	params := url.Values{"client_id": {client.ClientID}, "redirect_uri": {client.RedirectURIs[0]}, "response_type": {"code"}, "scope": {"openid profile email offline_access"}, "state": {"composition-state"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "prompt": {"consent"}}
	consent := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), "", http.Header{"Accept": {"text/html"}})
	compositionStatus(t, consent, 200)
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(consent.body)
	if len(csrf) != 2 {
		t.Fatal("missing OIDC consent CSRF")
	}
	approved := f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {html.UnescapeString(string(csrf[1]))}, "decision": {"allow"}}.Encode(), http.Header{"Origin": {f.origin}, "Content-Type": {"application/x-www-form-urlencoded"}})
	code := compositionCode(t, approved)
	// An unredeemed code and its consent must survive too.
	f.replace(t, false, "")
	tokens := f.exchange(t, client, code, client.ClientSecret)
	compositionStatus(t, tokens, 200)
	first := compositionJSON(t, tokens)["refresh_token"].(string)
	refresh := func(token string) compositionResponse {
		headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client.ClientID)+":"+url.QueryEscape(client.ClientSecret)))}}
		return f.request(t, "POST", "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}.Encode(), headers)
	}
	f.replace(t, false, "")
	rotated := refresh(first)
	compositionStatus(t, rotated, 200)
	next := compositionJSON(t, rotated)["refresh_token"].(string)
	f.replace(t, false, "")
	compositionStatus(t, refresh(first), 400)
	f.replace(t, false, "")
	compositionStatus(t, refresh(next), 400)
	// Revoking a different live grant's browser session must also remain durable.
	liveCode := compositionCode(t, f.authorize(t, client))
	liveTokens := f.exchange(t, client, liveCode, client.ClientSecret)
	compositionStatus(t, liveTokens, 200)
	liveAccess := compositionJSON(t, liveTokens)["access_token"].(string)
	browserURL, _ := url.Parse(f.issuer)
	oldCookies := f.client.Jar.Cookies(browserURL)
	headers := http.Header{"Origin": {f.origin}, "Content-Type": {"application/json"}, "X-Authcrunch-Refresh": {"1"}}
	compositionStatus(t, f.request(t, "POST", "/api/logout", "{}", headers), 200)
	f.replace(t, false, "")
	f.client.Jar.SetCookies(browserURL, oldCookies)
	compositionStatus(t, f.request(t, "GET", "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + liveAccess}}), 401)
	compositionStatus(t, f.request(t, "POST", "/api/refresh_token", "{}", headers), 401)
}

func TestE2EServerPersistentLoginCommitFailure(t *testing.T) {
	stateConfig := persistentTestConfig(t)
	f := newServerCompositionFixture(t, false, func(c *authcrunch.Config) { c.State = stateConfig })
	// Commit the empty OIDC snapshot first, so clearing a nonexistent session
	// during login is a no-op. The injected failure must occur at final issuance.
	compositionStatus(t, f.request(t, "GET", "/oidc/userinfo", "", http.Header{"Authorization": {"Bearer " + strings.Repeat("x", 43)}}), 401)
	sessionHash := sha256.Sum256([]byte("portal-sessions/portal"))
	sessionFile := filepath.Join(stateConfig.Directory, fmt.Sprintf("%x.state", sessionHash))
	before, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Jar, _ = cookiejar.New(nil)
	headers := http.Header{"Origin": {f.origin}, "Content-Type": {"application/x-www-form-urlencoded"}}
	start := f.request(t, "POST", "/login", url.Values{"realm": {"local"}, "username": {"alice"}}.Encode(), headers)
	compositionStatus(t, start, 303)
	target := start.header.Get("Location")
	compositionStatus(t, f.request(t, "POST", target, url.Values{"secret": {tests.TestPwd1}}.Encode(), headers), 303)
	// Only the later OIDC session commit fails; portal session and refresh writes
	// succeed first and prepare cookies. None may reach the browser on this error.
	hash := sha256.Sum256([]byte("oidc/portal"))
	if err := os.Mkdir(filepath.Join(stateConfig.Directory, fmt.Sprintf("%x.state.pending", hash)), 0700); err != nil {
		t.Fatal(err)
	}
	failed := f.request(t, "GET", target, "", nil)
	compositionStatus(t, failed, 503)
	after, err := os.ReadFile(sessionFile)
	if err != nil || bytes.Equal(before, after) {
		t.Fatal("injected failure occurred before portal session commit")
	}
	if failed.header.Get("Set-Cookie") != "" || failed.header.Get("Authorization") != "" || failed.header.Get("Location") != "" {
		t.Fatal("failed commit delivered credentials or redirect")
	}
	compositionStatus(t, f.request(t, "GET", "/portal", "", nil), 503)
	// Close deliberately reports the poisoned store; retire the fixture's handle
	// after asserting that expected error.
	f.mu.Lock()
	err = f.active.Close()
	f.active = nil
	f.mu.Unlock()
	if err == nil {
		t.Fatal("poisoned store closed without error")
	}
}

func TestE2EServerPersistentStorageOwnershipAndFailure(t *testing.T) {
	stateConfig := persistentTestConfig(t)
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) { c.State = stateConfig })
	var cfg authcrunch.Config
	if err := json.Unmarshal(f.config, &cfg); err != nil {
		t.Fatal(err)
	}
	duplicate, err := authcrunch.NewServer(&cfg, zap.NewNop())
	if err == nil {
		_ = duplicate.Close()
		t.Fatal("two runtimes own the same directory")
	}
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), 303)
	if err := f.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("oauth-sessions/primary"))
	filename := filepath.Join(stateConfig.Directory, fmt.Sprintf("%x.state", hash))
	if err := os.WriteFile(filename, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.config, &cfg); err != nil {
		t.Fatal(err)
	}
	corrupt, err := authcrunch.NewServer(&cfg, zap.NewNop())
	if err == nil {
		_ = corrupt.Close()
		t.Fatal("corrupt state accepted")
	}
	// Failure during component restoration must unwind provider workers and the
	// directory lease. The low-level store can reacquire it for explicit recovery.
	recovered, err := state.Open(stateConfig)
	if err != nil {
		t.Fatal("failed construction leaked storage ownership", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}
