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
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	adminparser "github.com/greenpau/go-authcrunch/pkg/authn/admin_api/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func connectedFixture(t *testing.T, attached bool, configure ...func(*authn.PortalConfig)) (*oidcE2EPortal, *oidcE2EFixture) {
	t.Helper()
	issuer := newOIDCE2EIssuer(t, "Ed25519", "opaque", "", false)
	issuer.identityClaims = map[string]any{"sub": "stable-external-subject", "email": "keymember@example.test"}
	p := newOIDCE2EPortal(t, issuer, "/auth", "HS512", "discovery", oidcE2ETrustConfig{attached: attached, configurePortal: func(c *authn.PortalConfig) {
		c.AccessListConfigs = []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer authp/user"}, Action: "allow stop"}}
		for _, apply := range configure {
			apply(c)
		}
	}})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	p.client.Jar = jar
	return p, &oidcE2EFixture{server: p.server, client: p.client, issuer: p.server.URL + p.base}
}

func connectedLogin(t *testing.T, p *oidcE2EPortal, f *oidcE2EFixture, want int) oidcE2EResponse {
	t.Helper()
	location := p.server.URL + p.base + "/oauth2/" + p.realm
	var response oidcE2EResponse
	for step := range 3 {
		response = f.request(t, http.MethodGet, location, nil, nil)
		if step < 2 {
			oidcE2EStatus(t, response, http.StatusFound)
			location = response.header.Get("Location")
		}
	}
	oidcE2EStatus(t, response, want)
	return response
}

func connectionForm(t *testing.T, response oidcE2EResponse) (string, string) {
	t.Helper()
	oidcE2EStatus(t, response, http.StatusOK)
	path := regexp.MustCompile(`action="([^"]*/connected-accounts/[^"]+)"`).FindSubmatch(response.body)
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(response.body)
	if len(path) != 2 || len(csrf) != 2 {
		t.Fatal("connection page did not provide a form")
	}
	return html.UnescapeString(string(path[1])), html.UnescapeString(string(csrf[1]))
}

func TestE2EConnectedAccountsAutomaticAndExplicit(t *testing.T) {
	p, f := connectedFixture(t, true)
	connectedLogin(t, p, f, http.StatusSeeOther)
	first := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	firstID, _ := first["id"].(string)
	if firstID == "" || firstID == "stable-external-subject" {
		t.Fatal("external login lacks an independent local ID")
	}
	// Matching email never selects the existing local account.
	db, err := identity.NewDatabase(p.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var localID string
	for _, u := range db.Users {
		if u.Username == "keymember" {
			localID = u.ID
		}
	}
	if firstID == localID || localID == "" {
		t.Fatal("email matched or local identity missing")
	}
	connectedLogin(t, p, f, http.StatusSeeOther)
	repeated := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if repeated["id"] != firstID {
		t.Fatal("repeat login changed local ID")
	}
	if first["nonce"] == nil || first["nonce"] == "" || repeated["nonce"] == nil || repeated["nonce"] == "" || first["nonce"] == repeated["nonce"] {
		t.Fatal("repeat external login reused its access nonce")
	}
	endpoint, csrf := connectionForm(t, f.request(t, http.MethodGet, "/connected-accounts", nil, nil))
	previousAccess := loginIdentityCookie(f, "oauth_portal_token")
	origin := http.Header{"Origin": {p.server.URL}}
	form := url.Values{"csrf": {csrf}, "action": {"start"}}
	// A second authenticated browser cannot use or consume the first browser's
	// ticket, even when both upstream logins identify the same local record.
	otherJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherClient := *p.client
	otherClient.Jar = otherJar
	other := &oidcE2EFixture{server: p.server, client: &otherClient, issuer: f.issuer}
	connectedLogin(t, p, other, http.StatusSeeOther)
	oidcE2EStatus(t, other.request(t, http.MethodPost, p.server.URL+endpoint, form, origin), http.StatusGone)
	oidcE2EStatus(t, f.request(t, http.MethodPost, p.server.URL+endpoint, url.Values{"csrf": {csrf, csrf}, "action": {"start"}}, origin), http.StatusBadRequest)
	oidcE2EStatus(t, f.request(t, http.MethodPost, p.server.URL+endpoint, form, http.Header{"Origin": {"https://attacker.example"}}), http.StatusForbidden)
	start := f.request(t, http.MethodPost, p.server.URL+endpoint, form, origin)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	loginURL := start.header.Get("Location")
	if !strings.Contains(loginURL, "fresh=1") {
		t.Fatal("connection did not require fresh authentication")
	}
	foreignLogin := other.request(t, http.MethodGet, loginURL, nil, nil)
	oidcE2EStatus(t, foreignLogin, http.StatusOK)
	if strings.Contains(string(foreignLogin.body), endpoint) || strings.Contains(string(foreignLogin.body), url.QueryEscape(endpoint)) {
		t.Fatal("another browser retained the connection return URL")
	}
	oidcE2EStatus(t, f.request(t, http.MethodGet, loginURL, nil, nil), http.StatusOK)
	login := f.request(t, http.MethodPost, loginURL, url.Values{"username": {"keymember"}, "realm": {"local"}}, origin)
	oidcE2EStatus(t, login, http.StatusSeeOther)
	sandbox := login.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
	completed := f.request(t, http.MethodGet, sandbox, nil, nil)
	oidcE2EStatus(t, completed, http.StatusSeeOther)
	if !strings.HasSuffix(completed.header.Get("Location"), endpoint) {
		t.Fatal("local login lost its bound connection destination")
	}
	// Reusing the browser session identifier must not let the previous external
	// JWT borrow the new local login's cached authentication evidence.
	replayClient := *f.client
	replayClient.Jar = nil
	replay := &oidcE2EFixture{server: f.server, client: &replayClient, issuer: f.issuer}
	cookieURL, err := url.Parse(f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	replayRequest, err := http.NewRequest(http.MethodGet, f.issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.client.Jar.Cookies(cookieURL) {
		if c.Name == "oauth_portal_token" {
			c.Value = previousAccess
		}
		replayRequest.AddCookie(c)
	}
	oidcE2EStatus(t, replay.request(t, http.MethodGet, p.server.URL+endpoint, nil, replayRequest.Header), http.StatusFound)
	replayHeaders := replayRequest.Header.Clone()
	replayHeaders.Set("Origin", p.server.URL)
	oidcE2EStatus(t, replay.request(t, http.MethodPost, p.server.URL+endpoint, url.Values{"csrf": {csrf}, "action": {"connect"}}, replayHeaders), http.StatusFound)
	// A current bearer token with only the browser binding cookie also cannot
	// authorize this cookie-based account-management interaction.
	replayRequest.Header.Del("Cookie")
	for _, c := range f.client.Jar.Cookies(cookieURL) {
		if c.Name != "oauth_portal_token" {
			replayRequest.AddCookie(c)
		}
	}
	replayRequest.Header.Set("Authorization", "Bearer "+loginIdentityCookie(f, "oauth_portal_token"))
	oidcE2EStatus(t, replay.request(t, http.MethodGet, p.server.URL+endpoint, nil, replayRequest.Header), http.StatusFound)
	replayRequest.Header.Del("Authorization")
	replayRequest.AddCookie(&http.Cookie{Name: "oauth_portal_token", Value: loginIdentityCookie(f, "oauth_portal_token")})
	replayRequest.AddCookie(&http.Cookie{Name: "oauth_portal_token", Value: previousAccess})
	oidcE2EStatus(t, replay.request(t, http.MethodGet, p.server.URL+endpoint, nil, replayRequest.Header), http.StatusFound)
	confirm, confirmCSRF := connectionForm(t, f.request(t, http.MethodGet, p.server.URL+endpoint, nil, nil))
	if confirm != endpoint || confirmCSRF != csrf {
		t.Fatal("connection confirmation changed operation")
	}
	oidcE2EStatus(t, f.request(t, http.MethodPost, p.server.URL+endpoint, url.Values{"csrf": {"wrong"}, "action": {"connect"}}, origin), http.StatusForbidden)
	form.Set("action", "connect")
	oidcE2EStatus(t, f.request(t, http.MethodPost, p.server.URL+endpoint, form, origin), http.StatusOK)
	oidcE2EStatus(t, f.request(t, http.MethodPost, p.server.URL+endpoint, form, origin), http.StatusGone)
	connectedLogin(t, p, f, http.StatusSeeOther)
	linked := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if linked["id"] != localID {
		t.Fatal("connected login did not use immutable local ID")
	}
	db, err = identity.NewDatabase(p.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range db.Users {
		if u.ID == firstID && (!u.Disabled || len(u.ExternalAccounts) != 0) {
			t.Fatal("source identity retained login authority")
		}
		if u.ID == localID && len(u.ExternalAccounts) != 1 {
			t.Fatal("connection did not persist")
		}
	}
	if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "connected login", Secret: loginIdentityTOTPSecret, Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true}}); err != nil {
		t.Fatal(err)
	}
	factor := connectedLogin(t, p, f, http.StatusSeeOther)
	if factor.header.Get("Authorization") != "" || !strings.Contains(factor.header.Get("Location"), "/sandbox/") {
		t.Fatal("external login bypassed local MFA")
	}
	factorURL := p.server.URL + factor.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, factorURL, url.Values{"passcode": {loginIdentityTOTP()}}, origin), http.StatusSeeOther)
	oidcE2EStatus(t, f.request(t, http.MethodGet, factorURL, nil, nil), http.StatusSeeOther)
	mfaClaims := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if mfaClaims["id"] != localID || !strings.Contains(fmt.Sprint(mfaClaims["amr"]), "otp") {
		t.Fatal("local MFA evidence or ID lost")
	}
	db, err = identity.NewDatabase(p.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DisableUser(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test"}}); err != nil {
		t.Fatal(err)
	}
	connectedLogin(t, p, f, http.StatusUnauthorized)
}

func TestE2EConnectedAccountsImplicitMemory(t *testing.T) {
	p, f := connectedFixture(t, false)
	connectedLogin(t, p, f, http.StatusSeeOther)
	first := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})["id"]
	connectedLogin(t, p, f, http.StatusSeeOther)
	if first == nil || first == "" || first != providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})["id"] {
		t.Fatal("memory identity was not stable")
	}
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/connected-accounts", nil, nil), http.StatusForbidden)
	db, err := identity.NewDatabase(p.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Users) != 2 {
		t.Fatal("implicit provider wrote to named local store")
	}
}

func TestE2EConnectedAccountsAdministration(t *testing.T) {
	p, f := connectedFixture(t, true, func(c *authn.PortalConfig) {
		c.AccessListConfigs = []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer authp/user authp/admin"}, Action: "allow stop"}}
		config, err := adminparser.NewAdminAPIConfigFromDirectives([]string{"enable admin api"})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.ConfigureAdminAPI(config); err != nil {
			t.Fatal(err)
		}
	})
	connectedLogin(t, p, f, http.StatusSeeOther)
	first := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	db, err := identity.NewDatabase(p.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var username string
	for _, u := range db.Users {
		if u.ID == first["id"] {
			username = u.Username
		}
	}
	if username == "" {
		t.Fatal("automatic local identity missing")
	}
	request := map[string]any{"realm": "local", "operation": "info", "user": map[string]any{"username": username}}
	origin := http.Header{"Origin": {p.server.URL}}
	oidcE2EStatus(t, f.jsonRequest(t, "/api/server/user", request, "", origin), http.StatusForbidden)
	adminClient := *f.client
	adminClient.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	admin := &oidcE2EFixture{server: p.server, client: &adminClient, issuer: f.issuer}
	login := admin.request(t, http.MethodPost, "/login", url.Values{"username": {"keyadmin"}, "realm": {"local"}}, origin)
	oidcE2EStatus(t, login, http.StatusSeeOther)
	sandbox := login.header.Get("Location")
	oidcE2EStatus(t, admin.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
	oidcE2EStatus(t, admin.request(t, http.MethodGet, sandbox, nil, origin), http.StatusSeeOther)
	if loginIdentityCookie(admin, "oauth_portal_token") == "" {
		t.Fatal("local administrator login did not issue credentials")
	}
	validateResponse, validateComponent := openAPIContractValidators(t)
	act := func(operation string, fields map[string]any, want int) map[string]any {
		t.Helper()
		if fields == nil {
			fields = map[string]any{"username": username}
		}
		payload := map[string]any{"realm": "local", "operation": operation, "user": fields}
		response := admin.jsonRequest(t, "/api/server/user", payload, "", origin)
		if response.status != want {
			t.Fatalf("admin %s: HTTP %d, want %d", operation, response.status, want)
		}
		validateResponse(t, "/api/server/user", http.MethodPost, response.status, response.header, response.body)
		if want == http.StatusOK {
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			var wire any
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			validateComponent(t, "AdminUserRequest", wire)
		}
		var result map[string]any
		if err := json.Unmarshal(response.body, &result); err != nil {
			t.Fatal("invalid administrative response")
		}
		return result
	}
	status := func(result map[string]any, want string) {
		t.Helper()
		if result["status"] != want {
			t.Fatalf("administrative result differs from %s (body withheld)", want)
		}
	}
	if info := act("info", nil, http.StatusOK); info["id"] != first["id"] || info["externally_provisioned"] != true {
		t.Fatal("admin lookup selected a different identity")
	}
	act("info", map[string]any{"username": username, "email": false}, http.StatusBadRequest)
	act("add", map[string]any{"username": "newmember", "name": "New Member", "roles": []string{"viewer"}}, http.StatusBadRequest)
	status(act("disable", map[string]any{"username": "keymember"}, http.StatusOK), "failure")
	status(act("disable", map[string]any{"username": username, "email": "keymember@example.test"}, http.StatusOK), "failure")
	for _, operation := range []string{"overwrite_roles", "add_roles"} {
		status(act(operation, map[string]any{"username": username, "roles": []string{"attached/managed"}}, http.StatusOK), "success")
	}
	status(act("disable", nil, http.StatusOK), "success")
	connectedLogin(t, p, f, http.StatusUnauthorized)
	status(act("enable", map[string]any{"username": username, "email": ""}, http.StatusOK), "success")
	connectedLogin(t, p, f, http.StatusSeeOther)
	current := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if current["id"] != first["id"] || !strings.Contains(fmt.Sprint(current["roles"]), "attached/managed") {
		t.Fatal("re-enabled login lost its identity or managed role")
	}
	reset := act("reset_password", nil, http.StatusOK)
	status(reset, "success")
	password, ok := reset["password"].(string)
	if !ok || password == "" {
		t.Fatal("administrator password reset omitted generated credentials")
	}
	status(act("overwrite_auth_challenges", map[string]any{"username": username, "challenges": []string{"password"}}, http.StatusOK), "success")
	challenge := connectedLogin(t, p, f, http.StatusSeeOther)
	if challenge.header.Get("Authorization") != "" || !strings.Contains(challenge.header.Get("Location"), "/sandbox/") {
		t.Fatal("administrative local password requirement was bypassed")
	}
	challengeURL := p.server.URL + challenge.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, challengeURL, url.Values{"secret": {password}}, origin), http.StatusSeeOther)
	oidcE2EStatus(t, f.request(t, http.MethodGet, challengeURL, nil, origin), http.StatusSeeOther)
	verified := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if verified["id"] != first["id"] || !strings.Contains(fmt.Sprint(verified["amr"]), "pwd") {
		t.Fatal("attached local password did not preserve identity and verified evidence")
	}
	status(act("delete", nil, http.StatusOK), "success")
	connectedLogin(t, p, f, http.StatusSeeOther)
	recreated := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if recreated["id"] == first["id"] || strings.Contains(fmt.Sprint(recreated["roles"]), "attached/managed") {
		t.Fatal("deleted identity or managed role survived reprovisioning")
	}
	db, err = identity.NewDatabase(p.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Users) != 3 {
		t.Fatal("administrative lifecycle duplicated or removed an unrelated identity")
	}
	for _, u := range db.Users {
		if u.ID == first["id"] || u.ExternallyProvisioned && len(u.EmailAddresses) != 0 || u.Username == "keymember" && u.Disabled {
			t.Fatal("administrative mutations crossed the local selector boundary")
		}
	}
}

func TestE2EConnectedAccountsMemoryFilesystemIsolation(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	p, f := connectedFixture(t, false)
	// An ordinary file named like the sentinel must not seed an implicit store,
	// even when it already contains this exact verified provider identity.
	file := filepath.Join(dir, ":memory:")
	disk, err := identity.NewDatabase(file)
	if err != nil {
		t.Fatal(err)
	}
	account := identity.ExternalAccount{Provider: "upstream", Kind: "oauth", Issuer: p.issuer.server.URL, Subject: "stable-external-subject"}
	seeded, err := disk.ResolveExternalAccount(t.Context(), account, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.AddUserRoles(&requests.Request{User: requests.User{Username: seeded.Identity.Username, Roles: []string{"disk-only-admin"}}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	connectedLogin(t, p, f, http.StatusSeeOther)
	claims := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")})
	if claims["id"] == seeded.Evidence.UserID || strings.Contains(fmt.Sprint(claims["roles"]), "disk-only-admin") {
		t.Fatal("implicit provider inherited a filesystem identity or role")
	}
	if claims["id"] == nil || claims["id"] == "" {
		t.Fatal("implicit provider did not provision a local identity")
	}
	connectedLogin(t, p, f, http.StatusSeeOther)
	if next := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "oauth_portal_token")}); next["id"] != claims["id"] {
		t.Fatal("isolated memory identity changed on repeated login")
	}
	// The portal cookie is scoped to /auth; the separate protected application
	// uses the same signed token through its supported bearer transport.
	access := http.Header{"Authorization": {"Bearer " + loginIdentityCookie(f, "oauth_portal_token")}}
	oidcE2EStatus(t, f.request(t, http.MethodGet, p.server.URL+"/protected", nil, access), http.StatusOK)
	after, err := os.ReadFile(file)
	if err != nil || string(before) != string(after) {
		t.Fatal("implicit login modified the filesystem database", err)
	}
}

func TestE2EConnectedAccountsRequireNewLocalLogin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, f := connectedFixture(t, true)
		local := crossDeviceBrowser(f)
		origin := http.Header{"Origin": {p.server.URL}}
		login := local.request(t, http.MethodPost, "/login?fresh=1", url.Values{"username": {"keymember"}, "realm": {"local"}}, origin)
		oidcE2EStatus(t, login, http.StatusSeeOther)
		sandbox := login.header.Get("Location")
		oidcE2EStatus(t, local.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
		oidcE2EStatus(t, local.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
		previousLocalToken := loginIdentityCookie(local, "oauth_portal_token")
		if previousLocalToken == "" {
			t.Fatal("local session fixture did not authenticate")
		}
		connectedLogin(t, p, f, http.StatusSeeOther)
		endpoint, csrf := connectionForm(t, f.request(t, http.MethodGet, "/connected-accounts", nil, nil))
		start := f.request(t, http.MethodPost, p.server.URL+endpoint, url.Values{"csrf": {csrf}, "action": {"start"}}, origin)
		oidcE2EStatus(t, start, http.StatusSeeOther)
		// The clock is fixed: the older local login and later operation start
		// share a Unix second. A valid copied session is not a new local login.
		cookieURL, err := url.Parse(f.issuer)
		if err != nil {
			t.Fatal(err)
		}
		f.client.Jar.SetCookies(cookieURL, []*http.Cookie{{Name: "oauth_portal_token", Value: previousLocalToken, Path: "/", Secure: true}})
		attempt := f.request(t, http.MethodPost, p.server.URL+endpoint, url.Values{"csrf": {csrf}, "action": {"connect"}}, origin)
		oidcE2EStatus(t, attempt, http.StatusForbidden)
		db, err := identity.NewDatabase(p.databasePath)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range db.Users {
			if u.Username == "keymember" && len(u.ExternalAccounts) != 0 {
				t.Fatal("older local session connected an external identity")
			}
		}
		// A real local login started by this operation succeeds in that same
		// frozen second. Requiring the next clock tick would reject this flow.
		loginURL := start.header.Get("Location")
		oidcE2EStatus(t, f.request(t, http.MethodGet, loginURL, nil, nil), http.StatusOK)
		login = f.request(t, http.MethodPost, loginURL, url.Values{"username": {"keymember"}, "realm": {"local"}}, origin)
		oidcE2EStatus(t, login, http.StatusSeeOther)
		sandbox = login.header.Get("Location")
		oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
		oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
		oidcE2EStatus(t, f.request(t, http.MethodPost, p.server.URL+endpoint, url.Values{"csrf": {csrf}, "action": {"connect"}}, origin), http.StatusOK)
	})
}

func TestE2EConnectedAccountsBrowser(t *testing.T) {
	p, _ := connectedFixture(t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var spki []string
	for _, certificate := range [][]byte{p.server.Certificate().RawSubjectPublicKeyInfo, p.issuer.server.Certificate().RawSubjectPublicKeyInfo} {
		sum := sha256.Sum256(certificate)
		spki = append(spki, base64.StdEncoding.EncodeToString(sum[:]))
	}
	profile := t.TempDir()
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t), "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+strings.Join(spki, ","), "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	screenshots := os.Getenv("AUTHCRUNCH_CONNECTED_SCREENSHOT_DIR")
	if screenshots == "" {
		screenshots = t.TempDir()
	}
	params, err := json.Marshal(map[string]string{"origin": p.server.URL, "screenshots": screenshots})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/connected_accounts_browser_e2e.cjs", endpoint, string(params))
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("connected account browser journey failed: %v: %s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not verify connection")
	}
}

func TestE2EConnectedAccountsRefreshMFA(t *testing.T) {
	f := newProviderRefreshE2E(t, providerRefreshE2EOptions{attached: true, edit: func(c *authn.PortalConfig) {
		crossDeviceConfig(t, c)
		// Leave capacity available so a wrongly admitted requester family is
		// observable rather than hidden by the fixture's one-session limit.
		c.RefreshTokens.MaxSessions = 4
		c.OIDCProvider = &oidc.Config{Enabled: true, Issuer: c.RefreshTokens.PublicOrigin + "/auth", Realms: []string{"local"}, SigningKeyFiles: []string{"../../testdata/rskeys/test_1_pri.pem"}, Clients: []*oidc.ClientConfig{{ClientID: "connected-test", ClientSecret: oidcE2ESecret, RedirectURIs: []string{"https://rp.example.test/callback"}, RequirePKCE: true}}}
	}})
	f.issuer.identityClaims["sub"] = "stable-connected-subject"
	_, headers := f.login(t, http.StatusSeeOther)
	claims := providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
	db, err := identity.NewDatabase(f.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var account identity.ExternalAccount
	for _, u := range db.Users {
		if u.ID == claims["id"] && len(u.ExternalAccounts) == 1 {
			account = u.ExternalAccounts[0]
		}
	}
	source, err := db.ResolveExternalAccount(t.Context(), account, false)
	if err != nil {
		t.Fatal(err)
	}
	target := &requests.Request{User: requests.User{Username: "keymember", Password: tests.TestPwd1}}
	if err := db.AuthenticateUser(target); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConnectExternalAccount(t.Context(), account, source.Evidence, target.Authentication); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusUnauthorized {
		t.Fatal("moved source retained refresh authority", status)
	}
	if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "refresh factor", Secret: loginIdentityTOTPSecret, Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true}}); err != nil {
		t.Fatal(err)
	}
	portal := &oidcE2EFixture{server: f.server, client: f.client, issuer: f.server.URL + "/auth"}
	requester := crossDeviceBrowser(portal)
	interaction := crossDeviceStart(t, requester)
	crossDeviceBegin(t, portal, interaction)
	_, headers = f.login(t, http.StatusSeeOther)
	sandbox := headers.Get("Location")
	if !strings.Contains(sandbox, "/sandbox/") || headers.Get("Authorization") != "" {
		t.Fatal("refresh login bypassed local MFA")
	}
	origin := http.Header{"Origin": {f.server.URL}}
	oidcE2EStatus(t, portal.request(t, http.MethodPost, f.server.URL+sandbox, url.Values{"passcode": {loginIdentityTOTP()}}, origin), http.StatusSeeOther)
	oidcE2EStatus(t, portal.request(t, http.MethodGet, f.server.URL+sandbox, nil, nil), http.StatusSeeOther)
	if loginIdentityCookie(portal, "AUTHP_OIDC_SESSION_ID") != "" {
		t.Fatal("external MFA login acquired local OIDC authority")
	}
	approverClaims := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(portal, "oauth_portal_token")})
	confirmation := portal.request(t, http.MethodGet, "/cross-device/confirm", nil, nil)
	oidcE2EStatus(t, confirmation, http.StatusOK)
	oidcE2EStatus(t, crossDeviceDecision(t, portal, confirmation, "approve"), http.StatusOK)
	status, headers, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil)
	if status != http.StatusOK {
		t.Fatal("completed local factor did not renew", status)
	}
	claims = providerRefreshClaims(t, providerRefreshCookie(t, headers, "oauth_portal_token"))
	if claims["id"] != target.Authentication.UserID || !strings.Contains(fmt.Sprint(claims["amr"]), "otp") {
		t.Fatal("renewal lost attached ID or verified factor")
	}
	poll := crossDevicePost(t, requester, "poll", crossDevicePollValues(interaction))
	oidcE2EStatus(t, poll, http.StatusOK)
	transferred := providerRefreshClaims(t, providerRefreshCookie(t, poll.header, "oauth_portal_token"))
	if loginIdentityCookie(requester, "AUTHP_REFRESH_TOKEN") != "" || transferred["sid"] != nil {
		t.Fatal("external MFA transfer created a requester refresh family")
	}
	if transferred["id"] != target.Authentication.UserID || fmt.Sprint(transferred["amr"]) != "[federated otp]" || transferred["auth_time"] != approverClaims["auth_time"] {
		t.Fatal("external MFA transfer lost local identity or verified methods")
	}
	if transferred["exp"].(float64) > approverClaims["exp"].(float64) {
		t.Fatal("external MFA transfer extended the approving login")
	}
	if loginIdentityCookie(requester, "AUTHP_OIDC_SESSION_ID") != "" {
		t.Fatal("external MFA transfer acquired local OIDC authority")
	}
	oidcE2EStatus(t, requester.request(t, http.MethodGet, f.server.URL+"/protected", nil, nil), http.StatusOK)
	db, err = identity.NewDatabase(f.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DisableUser(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test"}}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := f.send(t, http.MethodPost, "/auth/api/refresh_token", "{}", nil); status != http.StatusUnauthorized {
		t.Fatal("disabled local account renewed provider snapshot", status)
	}
}
