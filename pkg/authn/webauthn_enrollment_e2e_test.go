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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func webAuthnEnrollmentBrowser(t *testing.T, source *oidcE2EFixture) *oidcE2EFixture {
	t.Helper()
	configured := source.server.Client()
	clientCopy := *configured
	client := &clientCopy
	client.Timeout = 10 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clone := *source
	clone.client = client
	return &clone
}

func webAuthnEnrollmentLogin(t *testing.T, f *oidcE2EFixture, username, password string) {
	t.Helper()
	origin := http.Header{"Origin": {f.server.URL}}
	start := f.request(t, http.MethodPost, "/login", url.Values{"username": {username}, "realm": {"local"}}, origin)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	sandbox := start.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {password}}, origin), http.StatusSeeOther)
	oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, origin), http.StatusSeeOther)
	if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") == "" {
		t.Fatal("browser login did not issue an access cookie")
	}
}

func webAuthnEnrollmentProfileRequest(t *testing.T, f *oidcE2EFixture, body map[string]any, want int) map[string]any {
	t.Helper()
	response := f.jsonRequest(t, "/api/profile", body, "", http.Header{"Origin": {f.server.URL}})
	if response.status != want {
		t.Fatalf("profile API returned HTTP %d, expected %d: %s", response.status, want, response.body)
	}
	var payload map[string]any
	if err := json.Unmarshal(response.body, &payload); err != nil {
		t.Fatal("profile API returned malformed JSON")
	}
	return payload
}

func webAuthnEnrollmentChallenge(t *testing.T, payload map[string]any) string {
	t.Helper()
	entry, ok := payload["entry"].(map[string]any)
	if !ok {
		t.Fatal("profile API omitted WebAuthn parameters")
	}
	challenge, ok := entry["challenge"].(string)
	if !ok || challenge == "" {
		t.Fatal("profile API omitted WebAuthn challenge")
	}
	return challenge
}

func webAuthnEnrollmentRegistration(t *testing.T, key *ecdsa.PrivateKey, credentialID, rpID, challenge, origin string, changed bool) string {
	t.Helper()
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	registration := identity.WebAuthnRegisterRequest{
		ID: credentialID, Type: "public-key", Transports: []string{"internal"}, Success: changed,
		ClientData: &identity.ClientData{Type: "webauthn.create", Challenge: challenge, Origin: origin},
		AttestationObject: &identity.AttestationObject{AuthData: &identity.AuthData{
			RelyingPartyID: fmt.Sprintf("%x", rpIDHash), Flags: map[string]bool{"UP": true, "AT": true},
			CredentialData: &identity.CredentialData{CredentialID: credentialID, PublicKey: map[string]any{
				"key_type": 2, "algorithm": -7, "curve_type": 1,
				"curve_x": base64.StdEncoding.EncodeToString(public[1:33]),
				"curve_y": base64.StdEncoding.EncodeToString(public[33:65]),
			}},
		}},
	}
	data, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func webAuthnEnrollmentIssue(t *testing.T, f *oidcE2EFixture) string {
	t.Helper()
	return webAuthnEnrollmentChallenge(t, webAuthnEnrollmentProfileRequest(t, f, map[string]any{
		"kind": "fetch_user_u2f_reg_params",
	}, http.StatusOK))
}

func webAuthnEnrollmentPrepare(t *testing.T, f *oidcE2EFixture, registration, challenge string, want int) string {
	t.Helper()
	payload := webAuthnEnrollmentProfileRequest(t, f, map[string]any{
		"kind": "fetch_user_u2f_ver_params", "webauthn_register": registration, "webauthn_challenge": challenge,
	}, want)
	if want != http.StatusOK {
		return ""
	}
	return webAuthnEnrollmentChallenge(t, payload)
}

func webAuthnEnrollmentVerify(t *testing.T, f *oidcE2EFixture, registration, registrationChallenge, assertion string, want int) {
	t.Helper()
	webAuthnEnrollmentProfileRequest(t, f, map[string]any{
		"kind": "test_user_u2f_reg", "webauthn_register": registration,
		"webauthn_challenge": registrationChallenge, "webauthn_request": assertion,
	}, want)
}

func webAuthnEnrollmentAdd(t *testing.T, f *oidcE2EFixture, registration, challenge string, want int) {
	t.Helper()
	webAuthnEnrollmentProfileRequest(t, f, map[string]any{
		"kind": "add_user_u2f_token", "webauthn_register": registration, "webauthn_challenge": challenge,
		"title": "PortalKey", "description": "TLS portal enrollment key", "labels": []string{"e2e"},
		"tags": []map[string]any{{"key": "source", "value": "tls"}},
	}, want)
}

func webAuthnEnrollmentRequireNoTokens(t *testing.T, store interface {
	Request(operator.Type, *requests.Request) error
}) {
	t.Helper()
	lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
	if err := store.Request(operator.GetMfaTokens, lookup); err != nil {
		t.Fatal(err)
	}
	if lookup.Response.Payload.(*identity.MfaTokenBundle).Size() != 0 {
		t.Fatal("rejected enrollment persisted a credential")
	}
}

func webAuthnEnrollmentLoginWithU2F(t *testing.T, source *oidcE2EFixture, key *ecdsa.PrivateKey, credentialID, wantSubject string) {
	t.Helper()
	login := webAuthnEnrollmentBrowser(t, source)
	webAuthnEnrollmentAuthenticateWithU2F(t, login, key, credentialID, wantSubject)
}

func webAuthnEnrollmentAuthenticateWithU2F(t *testing.T, login *oidcE2EFixture, key *ecdsa.PrivateKey, credentialID, wantSubject string) {
	t.Helper()
	portalURL, err := url.Parse(login.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	origin := http.Header{"Origin": {login.server.URL}}
	start := login.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	sandbox := start.header.Get("Location")
	oidcE2EStatus(t, login.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
	page := login.request(t, http.MethodGet, sandbox, nil, origin)
	oidcE2EStatus(t, page, http.StatusOK)
	match := webAuthnChallengePattern.FindSubmatch(page.body)
	if len(match) != 2 {
		t.Fatal("portal did not issue an assertion challenge for the enrolled credential")
	}
	parts := strings.Split(sandbox, "/sandbox/")
	if len(parts) != 2 {
		t.Fatal("portal returned a malformed sandbox location")
	}
	endpoint := parts[0] + "/sandbox/" + strings.SplitN(parts[1], "/", 2)[0] + "/mfa-u2f-auth"
	assertion := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), string(match[1]), login.server.URL)
	oidcE2EStatus(t, login.request(t, http.MethodPost, endpoint, url.Values{"webauthn_request": {assertion}}, origin), http.StatusSeeOther)
	oidcE2EStatus(t, login.request(t, http.MethodGet, sandbox, nil, origin), http.StatusSeeOther)
	loginIdentityClaims(t, login, loginIdentityCookie(login, "AUTHP_ACCESS_TOKEN"), wantSubject)
}

func TestE2EWebAuthnProfileEnrollmentBoundToTLSCeremony(t *testing.T) {
	for _, tc := range []struct {
		name, wantSubject string
		refresh           bool
	}{
		{name: "access-only", wantSubject: "bob"},
		{name: "renewed-refresh", wantSubject: "alice", refresh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, store, _ := newLoginIdentityE2E(t, tc.refresh, false, false, "bob")
			webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
			if tc.refresh {
				rotated := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{
					"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"},
				})
				oidcE2EStatus(t, rotated, http.StatusOK)
			}
			portalURL, err := url.Parse(f.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			const credentialID = "profile-enrollment-credential"

			issueRegistration := func(origin, registrationChallenge string, changed bool) (string, string) {
				t.Helper()
				challenge := webAuthnEnrollmentIssue(t, f)
				if registrationChallenge == "" {
					registrationChallenge = challenge
				}
				return challenge, webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), registrationChallenge, origin, changed)
			}

			challenge, registration := issueRegistration(f.server.URL, "", false)
			webAuthnEnrollmentAdd(t, f, registration, challenge, http.StatusBadRequest)

			challenge, registration = issueRegistration("https://evil."+portalURL.Host, "", false)
			webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusBadRequest)

			challenge, registration = issueRegistration(f.server.URL, "wrong-registration-challenge", false)
			webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusBadRequest)

			challenge, registration = issueRegistration(f.server.URL, "", false)
			webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusOK)
			wrongProof := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), "wrong-proof-challenge", f.server.URL)
			webAuthnEnrollmentVerify(t, f, registration, challenge, wrongProof, http.StatusBadRequest)

			otherAlice := webAuthnEnrollmentBrowser(t, f)
			webAuthnEnrollmentLogin(t, otherAlice, "alice", tests.TestPwd1)
			challenge, registration = issueRegistration(f.server.URL, "", false)
			webAuthnEnrollmentPrepare(t, otherAlice, registration, challenge, http.StatusBadRequest)

			bob := webAuthnEnrollmentBrowser(t, f)
			webAuthnEnrollmentLogin(t, bob, "bob", tests.TestPwd2)
			challenge, registration = issueRegistration(f.server.URL, "", false)
			webAuthnEnrollmentPrepare(t, bob, registration, challenge, http.StatusBadRequest)

			challenge, registration = issueRegistration(f.server.URL, "", false)
			proofChallenge := webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusOK)
			proof := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), proofChallenge, f.server.URL)
			webAuthnEnrollmentVerify(t, f, registration, challenge, proof, http.StatusOK)
			changedRegistration := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), challenge, f.server.URL, true)
			webAuthnEnrollmentAdd(t, f, changedRegistration, challenge, http.StatusBadRequest)

			challenge, registration = issueRegistration(f.server.URL, "", false)
			proofChallenge = webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusOK)
			proof = webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), proofChallenge, f.server.URL)
			webAuthnEnrollmentVerify(t, f, registration, challenge, proof, http.StatusOK)
			webAuthnEnrollmentAdd(t, f, registration, challenge, http.StatusOK)
			webAuthnEnrollmentAdd(t, f, registration, challenge, http.StatusUnauthorized)

			lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
			if err := store.Request(operator.GetMfaTokens, lookup); err != nil {
				t.Fatal(err)
			}
			tokens := lookup.Response.Payload.(*identity.MfaTokenBundle).Get()
			if len(tokens) != 1 || tokens[0].Type != "u2f" || tokens[0].Parameters["u2f_id"] != credentialID {
				t.Fatal("verified profile enrollment did not persist the registered credential")
			}
			bobLookup := &requests.Request{User: requests.User{Username: "bob", Email: "bob@example.test"}}
			if err := store.Request(operator.GetMfaTokens, bobLookup); err != nil {
				t.Fatal(err)
			}
			if bobLookup.Response.Payload.(*identity.MfaTokenBundle).Size() != 0 {
				t.Fatal("transformed presentation subject received the canonical account's credential")
			}

			if _, err := store.OverwriteUserAuthChallengeRules("alice", "alice@example.test", []string{"password u2f"}); err != nil {
				t.Fatal(err)
			}
			webAuthnEnrollmentLoginWithU2F(t, f, key, credentialID, tc.wantSubject)
		})
	}
}

func TestE2EWebAuthnProfileEnrollmentRejectsChangedIdentity(t *testing.T) {
	f, store, userID := newLoginIdentityE2E(t, false, false, false, "")
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	portalURL, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := webAuthnEnrollmentIssue(t, f)
	const credentialID = "changed-identity-enrollment-credential"
	registration := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), challenge, f.server.URL, false)
	proofChallenge := webAuthnEnrollmentPrepare(t, f, registration, challenge, http.StatusOK)
	proof := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), proofChallenge, f.server.URL)
	webAuthnEnrollmentVerify(t, f, registration, challenge, proof, http.StatusOK)

	if err := store.RevokeUserSessions(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	webAuthnEnrollmentAdd(t, f, registration, challenge, http.StatusUnauthorized)
	webAuthnEnrollmentRequireNoTokens(t, store)
}

func TestE2EWebAuthnSandboxEnrollmentUsesServerChallenge(t *testing.T) {
	f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs[0].Actions = append(cfg.UserTransformerConfigs[0].Actions, "require u2f")
	})
	portalURL, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origin := http.Header{"Origin": {f.server.URL}}
	start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	sandbox := start.header.Get("Location")
	oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
	parts := strings.Split(sandbox, "/sandbox/")
	endpoint := parts[0] + "/sandbox/" + strings.SplitN(parts[1], "/", 2)[0] + "/mfa-u2f-register"
	const credentialID = "sandbox-enrollment-credential"
	clientChallenge := "client-selected-registration-challenge"
	direct := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), clientChallenge, f.server.URL, false)
	if response := f.request(t, http.MethodPost, endpoint, url.Values{
		"webauthn_register": {direct}, "webauthn_challenge": {clientChallenge},
	}, origin); response.status == http.StatusSeeOther || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("sandbox accepted a registration before issuing its challenge")
	}
	webAuthnEnrollmentRequireNoTokens(t, store)

	page := f.request(t, http.MethodGet, endpoint, nil, origin)
	if page.status != http.StatusOK {
		t.Fatalf("sandbox registration page returned HTTP %d, location %q: %s", page.status, page.header.Get("Location"), page.body)
	}
	match := webAuthnChallengePattern.FindSubmatch(page.body)
	if len(match) != 2 {
		t.Fatal("sandbox did not render its server-issued registration challenge")
	}
	challenge := string(match[1])
	wrongOrigin := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), challenge, "https://evil."+portalURL.Host, false)
	if response := f.request(t, http.MethodPost, endpoint, url.Values{
		"webauthn_register": {wrongOrigin}, "webauthn_challenge": {challenge},
	}, origin); response.status == http.StatusSeeOther || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("sandbox accepted registration client data for a different origin")
	}
	webAuthnEnrollmentRequireNoTokens(t, store)

	wrongChallenge := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), "wrong-server-challenge", f.server.URL, false)
	if response := f.request(t, http.MethodPost, endpoint, url.Values{
		"webauthn_register": {wrongChallenge}, "webauthn_challenge": {challenge},
	}, origin); response.status == http.StatusSeeOther || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("sandbox accepted registration client data for a different challenge")
	}
	webAuthnEnrollmentRequireNoTokens(t, store)

	registration := webAuthnEnrollmentRegistration(t, key, credentialID, portalURL.Hostname(), challenge, f.server.URL, false)
	oidcE2EStatus(t, f.request(t, http.MethodPost, endpoint, url.Values{
		"webauthn_register": {registration}, "webauthn_challenge": {challenge},
	}, origin), http.StatusUnauthorized)
	oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, origin), http.StatusUnauthorized)
	if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("first-factor enrollment was treated as login proof")
	}

	lookup := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
	if err := store.Request(operator.GetMfaTokens, lookup); err != nil {
		t.Fatal(err)
	}
	tokens := lookup.Response.Payload.(*identity.MfaTokenBundle).Get()
	if len(tokens) != 1 || tokens[0].Parameters["u2f_id"] != credentialID {
		t.Fatal("sandbox enrollment did not persist the server-bound credential")
	}
	webAuthnEnrollmentLoginWithU2F(t, f, key, credentialID, "alice")
}
