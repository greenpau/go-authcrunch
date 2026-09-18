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
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newIdentityAliasE2EStore(t *testing.T, source *local.IdentityStore, name string) *local.IdentityStore {
	t.Helper()
	path, ok := source.GetConfig()["path"].(string)
	if !ok || path == "" {
		t.Fatal("local store did not expose its configured database path")
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{
		Name: name, Kind: "local", Params: map[string]any{"path": path, "realm": name},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	return store.(*local.IdentityStore)
}

func identityAliasJSONPassword(t *testing.T, f *oidcE2EFixture, realm, password string) oidcE2EResponse {
	t.Helper()
	req := apiauth.AuthRequest{Username: "alice", Realm: realm}
	start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
	req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
	req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, password
	return f.jsonRequest(t, "/login", req, "", nil)
}

func TestE2EIdentityAliasRejectsRevokedPasswordAndStaleWrite(t *testing.T) {
	f, primary, _ := newLoginIdentityE2E(t, false, false, false, "")
	stale := newIdentityAliasE2EStore(t, primary, "stale-writer")
	change := &requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test",
		OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}
	if err := primary.Request(operator.ChangePassword, change); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.OverwriteUserRoles("alice", "alice@example.test", []string{"authp/user", "stale-role"}); err == nil {
		t.Fatal("stale alias overwrote a newer credential revision")
	}
	if response := identityAliasJSONPassword(t, f, "excluded", tests.TestPwd1); response.status == http.StatusOK {
		t.Fatal("portal alias authenticated a revoked password")
	}
	response := identityAliasJSONPassword(t, f, "excluded", tests.TestPwd2)
	result := loginIdentityResponse(t, response)
	if !result.Authenticated || result.AccessToken == "" {
		t.Fatal("portal alias did not authenticate the current password")
	}
}

func TestE2EIdentityAliasRejectsDeletedAPIKey(t *testing.T) {
	f, primary, _ := newLoginIdentityE2E(t, false, false, false, "")
	const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	if err := primary.Request(operator.AddAPIKey, &requests.Request{
		User: requests.User{Username: "alice", Email: "alice@example.test"},
		Key:  requests.Key{Payload: apiKey, Usage: "api", Comment: "alias deletion regression"},
	}); err != nil {
		t.Fatal(err)
	}

	login := func() oidcE2EResponse {
		return f.jsonRequest(t, "/login", apiauth.AuthRequest{Realm: "excluded", APIKey: apiKey}, "", nil)
	}
	accepted := loginIdentityResponse(t, login())
	if !accepted.Authenticated || accepted.AccessToken == "" {
		t.Fatal("stale realm did not authenticate the current API key")
	}
	loginIdentityClaims(t, f, accepted.AccessToken, "alice")

	lookup := &requests.Request{
		User: requests.User{Username: "alice", Email: "alice@example.test"},
		Key:  requests.Key{Usage: "api"},
	}
	if err := primary.Request(operator.GetAPIKeys, lookup); err != nil {
		t.Fatal(err)
	}
	keys := lookup.Response.Payload.(*identity.APIKeyBundle).Get()
	if len(keys) != 1 {
		t.Fatalf("got %d API keys, want 1", len(keys))
	}
	if err := primary.Request(operator.DeleteAPIKey, &requests.Request{
		User: requests.User{Username: "alice", Email: "alice@example.test"},
		Key:  requests.Key{ID: keys[0].ID, Usage: "api"},
	}); err != nil {
		t.Fatal(err)
	}

	denied := login()
	if denied.status != http.StatusUnauthorized {
		t.Fatalf("deleted API key login returned %d, want %d", denied.status, http.StatusUnauthorized)
	}
	var deniedBody apiauth.AuthResponse
	if err := json.Unmarshal(denied.body, &deniedBody); err != nil {
		t.Fatal("deleted API key login returned invalid JSON")
	}
	if deniedBody.Authenticated || deniedBody.AccessToken != "" {
		t.Fatal("deleted API key login returned access credentials")
	}

	password := loginIdentityResponse(t, identityAliasJSONPassword(t, f, "excluded", tests.TestPwd1))
	if !password.Authenticated || password.AccessToken == "" {
		t.Fatal("API key deletion disrupted password authentication")
	}
	loginIdentityClaims(t, f, password.AccessToken, "alice")
}

func TestE2EIdentityAliasRejectsRevokedRefreshIdentity(t *testing.T) {
	f, primary, id := newLoginIdentityConfiguredE2E(t, true, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.RefreshTokens.Realms = []string{"local", "excluded"}
	})
	origin := http.Header{"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}}
	req := apiauth.AuthRequest{Username: "alice", Realm: "excluded"}
	start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
	req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
	req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd1
	result := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
	if !result.Authenticated || loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") == "" {
		t.Fatal("alias login did not establish a refresh identity")
	}
	if err := primary.RevokeUserSessions(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	response := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{
		"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}, "X-Authcrunch-Refresh": {"1"},
	})
	if response.status != http.StatusUnauthorized {
		t.Fatalf("revoked alias refresh returned %d", response.status)
	}
}

func TestE2ERoleChangeRevokesProfileAndRefreshIdentity(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, true, false, false, "")
	origin := http.Header{"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}}
	_, result := replacementLogin(t, f, "alice", "local", "", tests.TestPwd1, false, origin)
	if !result.Authenticated || loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") == "" {
		t.Fatal("login did not establish renewable profile identity")
	}
	if _, err := store.OverwriteUserRoles("alice", "alice@example.test", []string{"removed"}); err != nil {
		t.Fatal(err)
	}
	profile := f.jsonRequest(t, "/api/profile", map[string]any{"kind": "fetch_user_info"}, "", origin)
	if profile.status != http.StatusUnauthorized {
		t.Fatalf("role-revoked profile returned %d", profile.status)
	}
	refresh := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{
		"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}, "X-Authcrunch-Refresh": {"1"},
	})
	if refresh.status != http.StatusUnauthorized {
		t.Fatalf("role-revoked refresh returned %d", refresh.status)
	}
}

func TestE2EIdentityAliasesShareMFALockout(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, false, false, true, "")
	for i := range 10 {
		realm := []string{"local", "excluded"}[i%2]
		req := apiauth.AuthRequest{Username: "alice", Realm: realm}
		start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
		req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
		req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd1
		factor := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
		req.SandboxID, req.SandboxSecret = factor.SandboxID, factor.SandboxSecret
		req.ChallengeKind = factor.NextChallenge

		validCodes := make(map[string]bool)
		for offset := -2; offset <= 2; offset++ {
			validCodes[loginIdentityTOTPAt(time.Now().Add(time.Duration(offset)*30*time.Second))] = true
		}
		for _, candidate := range []string{"000000", "111111", "222222", "333333", "444444", "555555"} {
			if !validCodes[candidate] {
				req.ChallengeResponse = candidate
				break
			}
		}
		if req.ChallengeResponse == "" {
			t.Fatal("could not select a deterministic invalid TOTP code")
		}
		if response := f.jsonRequest(t, "/login", req, "", nil); response.status == http.StatusOK {
			t.Fatalf("invalid MFA attempt %d unexpectedly succeeded", i+1)
		}
	}
	if err := store.Request(operator.CheckMfaLockout, &requests.Request{User: requests.User{Username: "alice"}}); err == nil {
		t.Fatal("ten failures split across realm aliases did not lock the identity")
	}
}

func TestE2EPasswordChangeInvalidatesPendingMFA(t *testing.T) {
	t.Run("totp", func(t *testing.T) {
		f, store, _ := newLoginIdentityE2E(t, false, false, true, "")
		req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
		start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
		req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
		req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd1
		factor := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
		req.SandboxID, req.SandboxSecret = factor.SandboxID, factor.SandboxSecret
		req.ChallengeKind, req.ChallengeResponse = factor.NextChallenge, loginIdentityTOTP()
		if err := store.Request(operator.ChangePassword, &requests.Request{User: requests.User{
			Username: "alice", Email: "alice@example.test", OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
		}}); err != nil {
			t.Fatal(err)
		}
		if response := f.jsonRequest(t, "/login", req, "", nil); response.status == http.StatusOK {
			t.Fatal("TOTP completed a revoked password checkpoint")
		}
	})

	t.Run("webauthn", func(t *testing.T) {
		f, store, _ := newLoginIdentityE2E(t, false, false, false, "")
		portalURL, err := url.Parse(f.server.URL)
		if err != nil {
			t.Fatal(err)
		}
		registration, key, credentialID := webAuthnE2ERegistration(t, portalURL.Hostname())
		if err := store.Request(operator.AddMfaToken, &requests.Request{
			User:     requests.User{Username: "alice", Email: "alice@example.test"},
			MfaToken: requests.MfaToken{Type: "u2f", Comment: "revocation test"}, WebAuthn: registration,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.OverwriteUserAuthChallengeRules("alice", "alice@example.test", []string{"password u2f"}); err != nil {
			t.Fatal(err)
		}
		headers := http.Header{"Origin": {f.server.URL}}
		start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, headers)
		oidcE2EStatus(t, start, http.StatusSeeOther)
		sandbox := start.header.Get("Location")
		oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, headers), http.StatusSeeOther)
		challengePage := f.request(t, http.MethodGet, sandbox, nil, headers)
		oidcE2EStatus(t, challengePage, http.StatusOK)
		match := webAuthnChallengePattern.FindSubmatch(challengePage.body)
		if len(match) != 2 {
			t.Fatal("portal did not render a WebAuthn challenge")
		}
		parts := strings.Split(sandbox, "/sandbox/")
		if len(parts) != 2 {
			t.Fatal("sandbox location is malformed")
		}
		endpoint := parts[0] + "/sandbox/" + strings.SplitN(parts[1], "/", 2)[0] + "/mfa-u2f-auth"
		if err := store.Request(operator.ChangePassword, &requests.Request{User: requests.User{
			Username: "alice", Email: "alice@example.test", OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
		}}); err != nil {
			t.Fatal(err)
		}
		assertion := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), string(match[1]), f.server.URL)
		response := f.request(t, http.MethodPost, endpoint, url.Values{"webauthn_request": {assertion}}, headers)
		if response.status == http.StatusSeeOther || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
			t.Fatal("WebAuthn completed a revoked password checkpoint")
		}
	})
}

func TestE2EStaleTOTPSandboxCannotConsumeOrLockCurrentIdentity(t *testing.T) {
	for _, flow := range []string{"html", "json"} {
		t.Run(flow, func(t *testing.T) {
			f, store, _ := newLoginIdentityE2E(t, false, false, true, "")
			origin := http.Header{"Origin": {f.server.URL}}
			var submitStale func(string) oidcE2EResponse
			if flow == "html" {
				start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
				oidcE2EStatus(t, start, http.StatusSeeOther)
				sandbox := start.header.Get("Location")
				oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
				submitStale = func(code string) oidcE2EResponse {
					return f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {code}}, origin)
				}
			} else {
				req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
				start := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
				req.SandboxID, req.SandboxSecret = start.SandboxID, start.SandboxSecret
				req.ChallengeKind, req.ChallengeResponse = start.NextChallenge, tests.TestPwd1
				factor := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
				req.SandboxID, req.SandboxSecret = factor.SandboxID, factor.SandboxSecret
				req.ChallengeKind = factor.NextChallenge
				submitStale = func(code string) oidcE2EResponse {
					req.ChallengeResponse = code
					return f.jsonRequest(t, "/login", req, "", nil)
				}
			}

			if err := store.Request(operator.ChangePassword, &requests.Request{User: requests.User{
				Username: "alice", Email: "alice@example.test", OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
			}}); err != nil {
				t.Fatal(err)
			}

			invalidCode := "000000"
			if invalidCode == loginIdentityTOTP() {
				invalidCode = "999999"
			}
			wantDenied := http.StatusUnauthorized
			if flow == "html" {
				wantDenied = http.StatusForbidden
			}
			for i := range 10 {
				if response := submitStale(invalidCode); response.status != wantDenied {
					t.Fatalf("stale invalid MFA attempt %d returned %d, want %d", i+1, response.status, wantDenied)
				}
			}
			if err := store.Request(operator.CheckMfaLockout, &requests.Request{User: requests.User{Username: "alice"}}); err != nil {
				t.Fatalf("stale sandbox altered current MFA lockout: %v", err)
			}

			at := time.Now()
			code := loginIdentityTOTPAt(at)
			if response := submitStale(code); response.status != wantDenied {
				t.Fatalf("stale valid MFA attempt returned %d, want %d", response.status, wantDenied)
			}
			getTokens := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
			if err := store.Request(operator.GetMfaTokens, getTokens); err != nil {
				t.Fatal(err)
			}
			for _, token := range getTokens.Response.Payload.(*identity.MfaTokenBundle).Get() {
				if token.Type == "totp" && token.LastTOTPCounter != nil {
					t.Fatal("stale sandbox consumed the current TOTP counter")
				}
			}

			if flow == "html" {
				start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
				oidcE2EStatus(t, start, http.StatusSeeOther)
				sandbox := start.header.Get("Location")
				oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd2}}, origin), http.StatusSeeOther)
				oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {code}}, origin), http.StatusSeeOther)
				oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, nil), http.StatusSeeOther)
				if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") == "" {
					t.Fatal("fresh HTML login did not issue an access token")
				}
				return
			}

			fresh := apiauth.AuthRequest{Username: "alice", Realm: "local"}
			freshStart := loginIdentityResponse(t, f.jsonRequest(t, "/login", fresh, "", nil))
			fresh.SandboxID, fresh.SandboxSecret = freshStart.SandboxID, freshStart.SandboxSecret
			fresh.ChallengeKind, fresh.ChallengeResponse = freshStart.NextChallenge, tests.TestPwd2
			freshFactor := loginIdentityResponse(t, f.jsonRequest(t, "/login", fresh, "", nil))
			fresh.SandboxID, fresh.SandboxSecret = freshFactor.SandboxID, freshFactor.SandboxSecret
			fresh.ChallengeKind, fresh.ChallengeResponse = freshFactor.NextChallenge, code
			result := loginIdentityResponse(t, f.jsonRequest(t, "/login", fresh, "", nil))
			if !result.Authenticated || result.AccessToken == "" {
				t.Fatal("fresh JSON login could not consume the current TOTP after stale attempts")
			}
		})
	}
}

func TestE2EDatabaseCopyLeavesPortalSourceWritable(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, false, false, false, "")
	path := store.GetConfig()["path"].(string)
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Copy(filepath.Join(t.TempDir(), "backup.json")); err != nil {
		t.Fatal(err)
	}
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test", OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	result := loginIdentityResponse(t, identityAliasJSONPassword(t, f, "local", tests.TestPwd2))
	if !result.Authenticated || result.AccessToken == "" {
		t.Fatal("portal could not use the source database after backup")
	}
}
