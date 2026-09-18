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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func profileSessionRequireFreshLogin(t *testing.T, f *oidcE2EFixture) {
	t.Helper()
	// The access JWT remains unexpired, but credential changes revoke the
	// underlying proof used by the profile API.
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/portal", nil, nil), http.StatusOK)
	oidcE2EStatus(t, f.request(t, http.MethodGet, "/profile/", nil, nil), http.StatusOK)
	webAuthnEnrollmentProfileRequest(t, f, map[string]any{"kind": "fetch_user_info"}, http.StatusUnauthorized)
	refresh := loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN")
	recovery := f.request(t, http.MethodGet, "/api/refresh_token", nil, http.Header{
		"Accept": {"text/html,application/xhtml+xml"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"},
	})
	oidcE2EStatus(t, recovery, http.StatusFound)
	if recovery.header.Get("Location") != f.issuer+"/login?fresh=1" {
		t.Fatal("profile recovery did not lead to a fresh login")
	}
	screen := f.request(t, http.MethodGet, recovery.header.Get("Location"), nil, nil)
	oidcE2EStatus(t, screen, http.StatusOK)
	if !strings.Contains(string(screen.body), `id="username"`) || screen.header.Get("Cache-Control") != "no-store" {
		t.Fatal("profile recovery did not render an uncached login form")
	}
	if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("fresh login retained the stale access cookie")
	}
	if loginIdentityCookie(f, "AUTHP_REFRESH_TOKEN") != refresh {
		t.Fatal("fresh login discarded the refresh credential before replacement")
	}
}

func TestE2EProfileSessionAfterMFAMutation(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprintf("refresh=%t", refresh), func(t *testing.T) {
			f, store, _ := newLoginIdentityE2E(t, refresh, false, false, "")
			webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			portalURL, err := url.Parse(f.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			const credentialID = "profile-session-passkey"
			challenge := webAuthnEnrollmentIssue(t, f)
			registration := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), challenge, f.server.URL, false)
			proofChallenge := webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusOK)
			assertion := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), proofChallenge, f.server.URL)
			webAuthnEnrollmentVerify(t, f, registration, challenge, assertion, http.StatusOK)
			webAuthnEnrollmentAdd(t, f, registration, challenge, http.StatusOK)

			profileSessionBrowserRecovery(t, f)
			profileSessionRequireFreshLogin(t, f)
			// Complete password and the newly enrolled passkey in the same browser,
			// without first visiting logout or editing the browser's cookies.
			webAuthnEnrollmentAuthenticateWithU2F(t, f, key, credentialID, "alice")
			webAuthnEnrollmentProfileRequest(t, f, map[string]any{"kind": "fetch_user_info"}, http.StatusOK)
			lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
			if err := store.Request(operator.GetMfaTokens, lookup); err != nil {
				t.Fatal(err)
			}
			tokens := lookup.Response.Payload.(*identity.MfaTokenBundle).Get()
			if len(tokens) != 1 {
				t.Fatal("passkey enrollment did not persist one factor")
			}
			webAuthnEnrollmentProfileRequest(t, f, map[string]any{
				"kind": "delete_user_multi_factor_authenticator", "id": tokens[0].ID,
			}, http.StatusOK)

			profileSessionBrowserRecovery(t, f)
			profileSessionRequireFreshLogin(t, f)
			webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
			webAuthnEnrollmentProfileRequest(t, f, map[string]any{"kind": "fetch_user_info"}, http.StatusOK)
			webAuthnEnrollmentRequireNoTokens(t, store)
		})
	}
}

// Give Chrome copies of the real login cookies so the shipped profile app,
// including its 401 navigation, runs against the same TLS portal and database.
func profileSessionBrowserRecovery(t *testing.T, f *oidcE2EFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	profile := t.TempDir()
	sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:]),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad",
		"--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	var cookies []map[string]any
	for name, path := range map[string]string{"AUTHP_ACCESS_TOKEN": "/", "AUTHP_REFRESH_TOKEN": "/auth"} {
		if value := loginIdentityCookie(f, name); value != "" {
			cookies = append(cookies, map[string]any{"name": name, "value": value, "url": f.issuer + "/portal", "path": path, "secure": true, "httpOnly": true, "sameSite": "Lax"})
		}
	}
	params, err := json.Marshal(map[string]any{"issuer": f.issuer, "cookies": cookies})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/profile_session_browser_e2e.cjs", endpoint)
	driver.Stdin = strings.NewReader(string(params))
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("profile browser recovery failed: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm profile session recovery")
	}
}
