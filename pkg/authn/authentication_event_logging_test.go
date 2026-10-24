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

package authn

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

const authenticationEventSuccess = "user was successfully authenticated"

func TestAuthenticationEventCheckpointAttribution(t *testing.T) {
	for _, flow := range []string{"json", "browser"} {
		for _, factor := range []string{"password", "totp", "u2f"} {
			t.Run(flow+"/"+factor, func(t *testing.T) {
				f := newRefreshPortal(t, false, factor == "totp")
				var hardwareKey *ecdsa.PrivateKey
				var badAssertion string
				if factor == "u2f" {
					registration, key := enrollmentTestRequest(t, "registration-challenge")
					hardwareKey = key
					registration.User = requests.User{Username: tests.TestUser1, Email: tests.TestEmail1}
					registration.MfaToken.Comment = "event fixture hardware"
					if err := f.store.Request(operator.AddMfaToken, registration); err != nil {
						t.Fatal("could not provision event hardware factor")
					}
					_, wrongKey := enrollmentTestRequest(t, "unused-registration")
					badAssertion = enrollmentTestProof(t, wrongKey, "event-private-challenge", refreshTestOrigin)
				}
				core, logs := observer.New(zap.InfoLevel)
				f.portal.logger = zap.New(core)
				rr := requests.NewRequest()
				rr.ID, rr.Upstream.SessionID = "event-request", "event-session"
				if err := f.portal.identifyUserRequest(rr, map[string]string{"username": tests.TestEmail1, "realm": "local"}); err != nil {
					t.Fatal("could not resolve alias for event fixture")
				}
				r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/login", nil)
				r.RequestURI = r.URL.RequestURI()
				usr, err := f.portal.createSandboxUser(t.Context(), httptest.NewRecorder(), r, rr)
				if err != nil {
					t.Fatal("could not create event sandbox")
				}
				usr.Checkpoints, err = user.NewCheckpoints([]string{factor})
				if err != nil {
					t.Fatal("could not create event checkpoint")
				}
				usr.Claims.Subject = "transformed-subject"
				usr.Authenticator.TempChallenge = "event-private-challenge"
				// JSON LDAP continuations can name their original public realm,
				// while the factor belongs to a separately bound local identity.
				rr.Upstream.Realm = "untrusted-request-realm"
				badValue := map[string]string{"password": tests.TestPwd2, "totp": "1234567", "u2f": badAssertion}[factor]
				verify := func(value string) error {
					form := url.Values{"secret": {value}, "passcode": {value}, "webauthn_request": {value}}
					r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/sandbox/fixture", strings.NewReader(form.Encode()))
					// Match the origin-form RequestURI supplied by an actual TLS
					// server, rather than httptest's absolute request target.
					r.RequestURI = r.URL.RequestURI()
					r.RemoteAddr = "192.0.2.18:49152"
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if origin, err := getWebAuthnExpectedOrigin(r); err != nil || origin != refreshTestOrigin {
						t.Fatal("checkpoint fixture did not preserve its expected TLS origin")
					}
					if flow == "json" {
						return f.portal.handleSandboxCheckpointVerification(t.Context(), r, rr, usr, &apiauth.AuthRequest{ChallengeKind: factor, ChallengeResponse: value})
					}
					action := map[string]string{"password": "auth", "totp": "mfa-app-auth", "u2f": "mfa-u2f-auth"}[factor]
					_, err := f.portal.nextSandboxCheckpoint(r, rr, usr, action)
					return err
				}
				if verify(badValue) == nil {
					t.Fatal("invalid factor was accepted")
				}
				checkpoint := usr.Checkpoints[0]
				if checkpoint.Passed || checkpoint.FailedAttempts != 1 || usr.Authorized || rr.Response.Authenticated {
					t.Fatal("failed checkpoint changed authentication evidence")
				}
				message := map[string]string{"password": "password authentication failed", "totp": "totp passcode authentication failed", "u2f": "u2f authentication failed"}[factor]
				entries := logs.FilterMessage(message).All()
				if len(entries) != 1 || entries[0].Level != zap.WarnLevel {
					t.Fatal("expected one exact WARN factor event")
				}
				fields := entries[0].ContextMap()
				for key, want := range map[string]any{
					"portal_name": "refresh-test", "realm": "local", "username": tests.TestUser1,
					"request_id": "event-request", "session_id": "event-session",
					"checkpoint_id": int64(checkpoint.ID), "checkpoint_name": checkpoint.Name, "checkpoint_type": factor,
					"src_ip": "192.0.2.18", "src_conn_ip": "192.0.2.18",
				} {
					if fields[key] != want {
						t.Fatalf("factor event field %s did not preserve attribution", key)
					}
				}
				assertAuthenticationSuccessEvents(t, logs, 0)
				assertAuthenticationEventSecrets(t, logs, badValue, refreshTestSecret, usr.Authenticator.TempSecret)
				// A correct assertion over exactly the same origin, challenge and
				// credential succeeds, isolating the prior hardware signature failure.
				if factor == "u2f" {
					goodAssertion := enrollmentTestProof(t, hardwareKey, usr.Authenticator.TempChallenge, refreshTestOrigin)
					inventory := &requests.Request{User: requests.User{Username: usr.LoginUsername, Email: usr.LoginEmail}}
					if f.store.Request(operator.GetMfaTokens, inventory) != nil {
						t.Fatal("hardware control could not read its stored credential")
					}
					bundle, ok := inventory.Response.Payload.(*identity.MfaTokenBundle)
					if !ok || bundle.Size() != 1 {
						t.Fatal("hardware control stored credential inventory is invalid")
					}
					parsed, err := bundle.Get()[0].WebAuthnRequest(goodAssertion)
					if err != nil || parsed == nil || parsed.ClientData == nil || parsed.ClientData.Origin != refreshTestOrigin || parsed.ClientData.Challenge != usr.Authenticator.TempChallenge {
						t.Fatal("hardware control signature or client metadata did not validate against its stored key")
					}
					if err := verify(goodAssertion); err != nil || !checkpoint.Passed {
						t.Fatalf("valid hardware control did not complete checkpoint: error=%t passed=%t", err != nil, checkpoint.Passed)
					}
				}
			})
		}
	}
}

func TestAuthenticationEventIncompleteJSONLogin(t *testing.T) {
	f := newRefreshPortal(t, true, true)
	core, logs := observer.New(zap.InfoLevel)
	f.portal.logger = zap.New(core)
	start := f.begin(t, "body")
	assertAuthenticationSuccessEvents(t, logs, 0)
	w := f.challenge(t, start, "body", "password", tests.TestPwd1)
	var next apiauth.AuthResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &next) != nil || next.NextChallenge == "" || next.Authenticated || next.AccessToken != "" || next.RefreshToken != "" {
		t.Fatal("incomplete factor journey changed its checkpoint response")
	}
	for _, cookie := range w.Result().Cookies() {
		if (cookie.Name == f.portal.cookie.AccessTokenCookieName || cookie.Name == f.portal.cookie.RefreshTokenCookieName || cookie.Name == f.portal.cookie.OIDCSessionIDCookieName) && cookie.Value != "" && cookie.MaxAge >= 0 && (cookie.Expires.IsZero() || cookie.Expires.After(time.Now())) {
			t.Fatal("incomplete checkpoint delivered a credential cookie")
		}
	}
	assertAuthenticationSuccessEvents(t, logs, 0)
	assertAuthenticationEventSecrets(t, logs, tests.TestPwd1, refreshTestSecret, start.SandboxSecret, next.SandboxSecret)
}

func assertAuthenticationSuccessEvents(t testing.TB, logs *observer.ObservedLogs, want int) {
	t.Helper()
	entries := logs.FilterMessage(authenticationEventSuccess).All()
	if len(entries) != want {
		t.Fatalf("exact JSON success event count %d, want %d", len(entries), want)
	}
	for _, entry := range entries {
		fields := entry.ContextMap()
		if entry.Level != zap.InfoLevel || fields["portal_name"] != "refresh-test" || fields["realm"] != "local" || fields["username"] != tests.TestUser1 || fields["authentication_flow"] != "api" {
			t.Fatal("JSON success event lost canonical attribution or severity")
		}
	}
}

func assertAuthenticationEventSecrets(t testing.TB, logs *observer.ObservedLogs, secrets ...string) {
	t.Helper()
	for _, entry := range logs.All() {
		encoded, err := json.Marshal(entry.ContextMap())
		if err != nil {
			t.Fatal("event fields could not be inspected")
		}
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			quoted, _ := json.Marshal(secret)
			if strings.Contains(entry.Message, secret) || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), string(quoted[1:len(quoted)-1])) {
				t.Fatal("authentication diagnostic exposed a fixture credential")
			}
		}
	}
}
