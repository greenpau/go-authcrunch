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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	challengeparser "github.com/greenpau/go-authcrunch/pkg/authchal/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

var authenticationChallengeChain = []string{"require auth challenges u2f", "require auth challenges password totp if u2f not available", "require auth challenges password if u2f and totp not available"}

func authenticationChallengeConfig(t *testing.T, rules []string) func(*authn.PortalConfig) {
	t.Helper()
	c, err := transformerparser.NewUserTransformerConfigFromDirectives(append([]string{"match realm local"}, rules...))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise persisted consumer configuration rather than a parser-only object.
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var restored transformer.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	return func(cfg *authn.PortalConfig) {
		cfg.UserTransformerConfigs = append(cfg.UserTransformerConfigs, &restored)
	}
}

func authenticationChallengeLogin(t *testing.T, f *oidcE2EFixture, flow string, sequence []string, key *ecdsa.PrivateKey, credentialID string) string {
	t.Helper()
	origin := http.Header{"Origin": {f.server.URL}}
	portalURL, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if flow == "html" {
		start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, origin)
		oidcE2EStatus(t, start, http.StatusSeeOther)
		sandbox := start.header.Get("Location")
		for _, kind := range sequence {
			switch kind {
			case "password":
				oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), http.StatusSeeOther)
			case "totp":
				oidcE2EStatus(t, f.request(t, http.MethodPost, sandbox, url.Values{"passcode": {loginIdentityTOTP()}}, origin), http.StatusSeeOther)
			case "u2f":
				page := f.request(t, http.MethodGet, sandbox, nil, origin)
				oidcE2EStatus(t, page, http.StatusOK)
				match := webAuthnChallengePattern.FindSubmatch(page.body)
				if len(match) != 2 {
					t.Fatal("expected hardware checkpoint without password")
				}
				assertion := webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), string(match[1]), f.server.URL)
				endpoint := strings.TrimRight(sandbox, "/") + "/mfa-u2f-auth"
				oidcE2EStatus(t, f.request(t, http.MethodPost, endpoint, url.Values{"webauthn_request": {assertion}}, origin), http.StatusSeeOther)
			}
		}
		oidcE2EStatus(t, f.request(t, http.MethodGet, sandbox, nil, origin), http.StatusSeeOther)
		token := loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
		if token == "" {
			t.Fatal("no access token after selected checkpoints")
		}
		return token
	}
	req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
	result := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
	for _, kind := range sequence {
		if result.Authenticated || result.NextChallenge != kind {
			t.Fatalf("expected %s checkpoint; got %s", kind, result.NextChallenge)
		}
		req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
		req.ChallengeKind = kind
		switch kind {
		case "password":
			req.ChallengeResponse = tests.TestPwd1
		case "totp":
			req.ChallengeResponse = loginIdentityTOTP()
		case "u2f", "mfa":
			req.ChallengeResponse = "webauthn"
			result = loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
			encoded := strings.TrimPrefix(result.NextChallenge, "mfa:u2f:")
			data, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal("malformed hardware challenge")
			}
			var challenge struct {
				Challenge string `json:"challenge"`
			}
			if json.Unmarshal(data, &challenge) != nil || challenge.Challenge == "" {
				t.Fatal("missing hardware challenge")
			}
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeKind = "u2f"
			req.ChallengeResponse = webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), challenge.Challenge, f.server.URL)
		}
		result = loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
	}
	if !result.Authenticated {
		t.Fatal("selected checkpoints did not complete login")
	}
	if result.AccessToken != "" {
		return result.AccessToken
	}
	token := loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
	if token == "" {
		t.Fatal("login omitted access cookie")
	}
	return token
}

func TestE2EAuthenticationChallengeSelection(t *testing.T) {
	gate, err := authz.NewGatekeeper(&authz.PolicyConfig{
		Name: "authentication-methods", AuthURLPath: "/login", AuthRedirectDisabled: true, ValidateBearerHeader: true,
		RawCryptoKeyStoreConfig: []string{"crypto key rsa-current verify from file ../../testdata/rskeys/test_2_pub.pem"},
		AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match amr hwk"}, Action: "allow stop"}},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	protected := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := requests.NewAuthorizationRequest()
		if err := gate.Authenticate(w, r, ar); err != nil || !ar.Response.Authorized {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(protected.Close)
	client := protected.Client()
	client.Timeout = 5 * time.Second
	for _, features := range []struct{ refresh, oidc bool }{{}, {refresh: true}, {oidc: true}, {refresh: true, oidc: true}} {
		refresh := features.refresh
		for _, flow := range []string{"html", "json"} {
			for _, factors := range []string{"password", "totp", "u2f", "both"} {
				t.Run(fmt.Sprintf("refresh=%t/oidc=%t/%s/%s", refresh, features.oidc, flow, factors), func(t *testing.T) {
					rules := append(append([]string(nil), authenticationChallengeChain...), "add amr forged")
					f, store, _ := newLoginIdentityConfiguredE2E(t, refresh, features.oidc, factors == "totp" || factors == "both", "", authenticationChallengeConfig(t, rules))
					var key *ecdsa.PrivateKey
					var credentialID string
					sequence := []string{"password"}
					want := "[pwd]"
					if factors == "totp" {
						sequence = []string{"password", "totp"}
						want = "[pwd otp]"
					}
					if factors == "u2f" || factors == "both" {
						portalURL, _ := url.Parse(f.server.URL)
						registration, k, id := webAuthnE2ERegistration(t, portalURL.Hostname())
						key, credentialID = k, id
						if err := store.Request(operator.AddMfaToken, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "selected factor"}, WebAuthn: registration}); err != nil {
							t.Fatal(err)
						}
						sequence = []string{"u2f"}
						want = "[hwk]"
					}
					token := authenticationChallengeLogin(t, f, flow, sequence, key, credentialID)
					claims := loginIdentityClaims(t, f, token, "alice")
					if fmt.Sprint(claims["amr"]) != want {
						t.Fatal("token reported unverified methods", claims["amr"])
					}
					if _, ok := claims["auth_methods"]; ok {
						t.Fatal("registered factors leaked into token")
					}
					request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, protected.URL+"/private", nil)
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Authorization", "Bearer "+token)
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					wantStatus := http.StatusForbidden
					if want == "[hwk]" {
						wantStatus = http.StatusNoContent
					}
					if response.StatusCode != wantStatus {
						t.Fatalf("protected application status %d, expected %d", response.StatusCode, wantStatus)
					}
					if features.oidc {
						code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
						tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
						if idClaims := f.verifyIDToken(t, tokens, "second"); fmt.Sprint(idClaims["amr"]) != want {
							t.Fatal("OIDC lost selected authentication methods")
						}
					}
					if refresh {
						rotated := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}})
						oidcE2EStatus(t, rotated, http.StatusOK)
						renewed := loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice")
						if fmt.Sprint(renewed["amr"]) != want {
							t.Fatal("renewal changed verified methods")
						}
					}
				})
			}
		}
	}
}

func TestE2EAuthenticationChallengePolicyBoundaries(t *testing.T) {
	t.Run("unavailable policy rejects login", func(t *testing.T) {
		f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", authenticationChallengeConfig(t, []string{"require auth challenges u2f"}))
		response := f.jsonRequest(t, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local"}, "", nil)
		if response.status == http.StatusOK {
			t.Fatal("unavailable policy fell back to password")
		}
	})
	t.Run("legacy requirement remains additive", func(t *testing.T) {
		f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, true, "", authenticationChallengeConfig(t, []string{"require auth challenges password", "require totp"}))
		token := authenticationChallengeLogin(t, f, "json", []string{"password", "totp"}, nil, "")
		if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[pwd otp]" {
			t.Fatal("legacy requirement was lost")
		}
	})
	t.Run("stored policy parser selects one alternative", func(t *testing.T) {
		f, store, _ := newLoginIdentityE2E(t, false, false, true, "")
		policy, err := challengeparser.NewAuthenticationChallengeConfigFromDirectives([]string{"u2f or totp"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.OverwriteUserAuthChallengeRules("alice", "alice@example.test", policy.Statements); err != nil {
			t.Fatal(err)
		}
		token := authenticationChallengeLogin(t, f, "json", []string{"totp"}, nil, "")
		if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[otp]" {
			t.Fatal("stored alternatives required an unavailable factor")
		}
	})
}

func TestE2EAuthenticationChallengeTOTPOnly(t *testing.T) {
	for _, features := range []struct{ refresh, oidc bool }{{}, {refresh: true}, {oidc: true}, {refresh: true, oidc: true}} {
		for _, flow := range []string{"html", "json"} {
			t.Run(fmt.Sprintf("refresh=%t/oidc=%t/%s", features.refresh, features.oidc, flow), func(t *testing.T) {
				f, _, _ := newLoginIdentityConfiguredE2E(t, features.refresh, features.oidc, true, "", authenticationChallengeConfig(t, []string{"require auth challenges totp", "add amr forged"}))
				// A real password is not an alternative to the selected TOTP.
				origin := http.Header{"Origin": {f.server.URL}}
				request := apiauth.AuthRequest{Username: "alice", Realm: "local"}
				start := loginIdentityResponse(t, f.jsonRequest(t, "/login", request, "", origin))
				if start.NextChallenge != "totp" || start.Authenticated {
					t.Fatal("TOTP-only selection retained a password checkpoint")
				}
				request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
				request.ChallengeKind, request.ChallengeResponse = "password", tests.TestPwd1
				oidcE2EStatus(t, f.jsonRequest(t, "/login", request, "", origin), http.StatusUnauthorized)
				token := authenticationChallengeLogin(t, f, flow, []string{"totp"}, nil, "")
				if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[otp]" {
					t.Fatal("TOTP-only token contained unverified methods")
				}
				if features.oidc {
					code := oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
					tokens := oidcE2ETokens(t, f.exchange(t, "second", code, oidcE2EVerifier))
					if claims := f.verifyIDToken(t, tokens, "second"); fmt.Sprint(claims["amr"]) != "[otp]" {
						t.Fatal("OIDC upgraded TOTP-only evidence")
					}
				}
				if features.refresh {
					oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}}), http.StatusOK)
					if claims := loginIdentityClaims(t, f, loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN"), "alice"); fmt.Sprint(claims["amr"]) != "[otp]" {
						t.Fatal("refresh upgraded TOTP-only evidence")
					}
				}
			})
		}
	}
}

func TestE2EAuthenticationChallengeCredentialRevocation(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprint(refresh), func(t *testing.T) {
			f, store, id := newLoginIdentityConfiguredE2E(t, refresh, false, true, "", authenticationChallengeConfig(t, authenticationChallengeChain))
			origin := http.Header{"Origin": {f.server.URL}}
			req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
			result := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeKind, req.ChallengeResponse = result.NextChallenge, tests.TestPwd1
			result = loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
			if result.Authenticated || result.NextChallenge != "totp" {
				t.Fatal("password completed two-factor policy")
			}
			if err := store.RevokeUserSessions(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeKind, req.ChallengeResponse = result.NextChallenge, loginIdentityTOTP()
			denied := f.jsonRequest(t, "/login", req, "", origin)
			if denied.status == http.StatusOK || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
				t.Fatal("revoked evidence completed selected policy")
			}
		})
	}
}

func TestE2EAuthenticationChallengeAPIKeyCannotCompletePolicy(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(fmt.Sprint(selected), func(t *testing.T) {
			rules := []string{"add amr forged"}
			if selected {
				rules = append(rules, "require auth challenges password")
			}
			f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", authenticationChallengeConfig(t, rules))
			const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
			if err := store.Request(operator.AddAPIKey, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "policy proof"}}); err != nil {
				t.Fatal(err)
			}
			response := f.jsonRequest(t, "/login", apiauth.AuthRequest{Realm: "local", APIKey: apiKey}, "", nil)
			if selected {
				oidcE2EStatus(t, response, http.StatusUnauthorized)
				return
			}
			result := loginIdentityResponse(t, response)
			claims := loginIdentityClaims(t, f, result.AccessToken, "alice")
			if _, ok := claims["amr"]; ok {
				t.Fatal("API key claimed unverified password/MFA")
			}
		})
	}
}

func TestE2EAuthenticationChallengeBasicLogin(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			rules := []string{"require auth challenges password", "add amr forged"}
			if extra {
				rules = append(rules, "require totp")
			}
			f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", authenticationChallengeConfig(t, rules))
			response := passwordAttemptBasic(t, f, "198.51.100.10", tests.TestPwd1)
			if extra {
				oidcE2EStatus(t, response, http.StatusForbidden)
				if response.header.Get("Authorization") != "" || loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
					t.Fatal("Basic login bypassed a selected policy requirement")
				}
				return
			}
			oidcE2EStatus(t, response, http.StatusSeeOther)
			token := loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")
			if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[pwd]" {
				t.Fatal("Basic login claimed unverified authentication")
			}
		})
	}
}

func TestE2EAuthenticationChallengeJSONWebAuthnProof(t *testing.T) {
	for _, mode := range []string{"generic mfa", "wrong factor", "wrong key", "wrong challenge"} {
		t.Run(mode, func(t *testing.T) {
			policy := "require auth challenges u2f"
			if mode == "generic mfa" {
				policy = "require auth challenges mfa"
			}
			f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, true, "", authenticationChallengeConfig(t, []string{policy}))
			portalURL, _ := url.Parse(f.server.URL)
			registration, key, credentialID := webAuthnE2ERegistration(t, portalURL.Hostname())
			if err := store.Request(operator.AddMfaToken, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "proof boundary"}, WebAuthn: registration}); err != nil {
				t.Fatal(err)
			}
			if mode == "generic mfa" {
				token := authenticationChallengeLogin(t, f, "json", []string{"mfa"}, key, credentialID)
				if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[hwk]" {
					t.Fatal("generic MFA lost the actual verified method")
				}
				return
			}
			req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
			result := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeKind, req.ChallengeResponse = "u2f", "webauthn"
			result = loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", nil))
			if result.Authenticated || result.AccessToken != "" {
				t.Fatal("requesting a challenge completed authentication")
			}
			data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result.NextChallenge, "mfa:u2f:"))
			if err != nil {
				t.Fatal("malformed WebAuthn challenge")
			}
			var challenge struct {
				Challenge string `json:"challenge"`
			}
			if json.Unmarshal(data, &challenge) != nil || challenge.Challenge == "" {
				t.Fatal("missing WebAuthn challenge")
			}
			if mode == "wrong key" {
				_, key, _ = webAuthnE2ERegistration(t, portalURL.Hostname())
			}
			if mode == "wrong challenge" {
				challenge.Challenge = "unissued-challenge"
			}
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeResponse = webAuthnE2EAssertion(t, key, credentialID, portalURL.Hostname(), challenge.Challenge, f.server.URL)
			if mode == "wrong factor" {
				req.ChallengeKind, req.ChallengeResponse = "totp", loginIdentityTOTP()
			}
			oidcE2EStatus(t, f.jsonRequest(t, "/login", req, "", nil), http.StatusUnauthorized)
			if loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN") != "" {
				t.Fatal("unverified assertion issued a credential")
			}
		})
	}
}
