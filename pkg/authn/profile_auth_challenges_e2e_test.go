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
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func profileAuthChallengeResponse(t *testing.T, response oidcE2EResponse, source string, rules, methods, effective, additional []string, changed bool) {
	t.Helper()
	oidcE2EStatus(t, response, http.StatusOK)
	var body struct {
		Entries                  []string `json:"entries"`
		RegisteredMethods        []string `json:"registered_methods"`
		EffectiveChallenges      []string `json:"effective_challenges"`
		AdditionalChallenges     []string `json:"additional_challenges"`
		PolicySource             string   `json:"policy_source"`
		ReauthenticationRequired bool     `json:"reauthentication_required"`
	}
	if err := json.Unmarshal(response.body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Entries == nil || body.RegisteredMethods == nil || body.EffectiveChallenges == nil || body.AdditionalChallenges == nil {
		t.Fatal("flow response returned null arrays")
	}
	if body.PolicySource != source || body.ReauthenticationRequired != changed || !slices.Equal(body.Entries, rules) || !slices.Equal(body.RegisteredMethods, methods) || !slices.Equal(body.EffectiveChallenges, effective) || !slices.Equal(body.AdditionalChallenges, additional) {
		t.Fatalf("unexpected flow response: %+v", body)
	}
	for _, secret := range []string{"credential_version", "private_key", "passwords", "mfa_tokens", "secret", "amr"} {
		if strings.Contains(string(response.body), `"`+secret+`"`) {
			t.Fatalf("flow metadata exposed %s", secret)
		}
	}
}

// Reopen the persisted database independently of the live portal/store cache.
func profileAuthChallengePersisted(t *testing.T, store *local.IdentityStore, name string) *identity.User {
	t.Helper()
	db, err := identity.NewDatabase(store.GetConfig()["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	rr := &requests.Request{User: requests.User{Username: name, Email: name + "@example.test"}}
	if err := db.GetUser(rr); err != nil {
		t.Fatal(err)
	}
	return rr.Response.Payload.(*identity.User)
}

func TestE2EProfileAuthenticationFlowSelection(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprintf("refresh_and_oidc=%t", refresh), func(t *testing.T) {
			f, store, _ := newLoginIdentityConfiguredE2E(t, refresh, refresh, false, "", func(cfg *authn.PortalConfig) {
				cfg.UserTransformerConfigs[0].Actions = []string{"overwrite sub bob", "overwrite email bob@example.test"}
			})
			portalURL, _ := url.Parse(f.server.URL)
			registration, key, credentialID := webAuthnE2ERegistration(t, portalURL.Hostname())
			if err := store.Request(operator.AddMfaToken, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "profile flow selection"}, WebAuthn: registration}); err != nil {
				t.Fatal(err)
			}
			before := profileAuthChallengePersisted(t, store, "alice")
			bob := profileAuthChallengePersisted(t, store, "bob")
			wantSubject := "bob"
			if refresh {
				// Refresh issuance restores the canonical subject after transforms.
				wantSubject = "alice"
			}
			token := authenticationChallengeLogin(t, f, "html", []string{"password", "u2f"}, key, credentialID)
			loginIdentityClaims(t, f, token, wantSubject)
			origin := http.Header{"Origin": {f.server.URL}}
			fetch := map[string]any{"kind": "fetch_user_auth_challenges"}
			profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", fetch, "", origin), "default", nil, []string{"password", "u2f"}, []string{"password", "u2f"}, nil, false)
			// Capture both an unfinished login and an OIDC code before mutation.
			native := replacementClientWithoutJar(f)
			pending := loginIdentityResponse(t, native.jsonRequest(t, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local"}, ""))
			var code string
			if refresh {
				code = oidcProviderE2ECode(t, f.request(t, http.MethodGet, "/oidc/authorize?"+f.authorization("second").Encode(), nil, nil))
			}
			// Neither transformed claims nor body identity selectors may target Bob.
			update := map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{"u2f"}, "username": "bob", "email": "bob@example.test", "realm": "excluded", "user_id": bob.ID}
			profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", update, "", origin), "user", []string{"u2f"}, []string{"password", "u2f"}, []string{"u2f"}, nil, true)
			after := profileAuthChallengePersisted(t, store, "alice")
			if after.ID != before.ID || after.CredentialVersion != before.CredentialVersion+1 || !slices.Equal(after.AuthChallengeRules, []string{"u2f"}) {
				t.Fatal("flow update did not atomically persist Alice's preference and revocation")
			}
			unchanged := profileAuthChallengePersisted(t, store, "bob")
			if unchanged.CredentialVersion != bob.CredentialVersion || len(unchanged.AuthChallengeRules) != 0 {
				t.Fatal("profile mutation changed the account named by transformed claims or payload")
			}
			oidcE2EStatus(t, f.jsonRequest(t, "/api/profile", fetch, "", origin), http.StatusUnauthorized)
			oidcE2EStatus(t, native.jsonRequest(t, "/api/profile", update, token), http.StatusUnauthorized)
			stale := native.jsonRequest(t, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local", SandboxID: pending.SandboxID, SandboxSecret: pending.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1}, "")
			if stale.status < 400 {
				t.Fatal("policy mutation retained an old login sandbox")
			}
			if refresh {
				oidcE2EStatus(t, f.exchange(t, "second", code, oidcE2EVerifier), http.StatusBadRequest)
				rotation := f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.server.URL}, "X-Authcrunch-Refresh": {"1"}})
				oidcE2EStatus(t, rotation, http.StatusUnauthorized)
			}
			profileSessionRequireFreshLogin(t, f)
			token = authenticationChallengeLogin(t, f, "html", []string{"u2f"}, key, credentialID)
			if claims := loginIdentityClaims(t, f, token, wantSubject); fmt.Sprint(claims["amr"]) != "[hwk]" {
				t.Fatal("selected passwordless flow did not produce verified hardware AMR")
			}
			profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", fetch, "", origin), "user", []string{"u2f"}, []string{"password", "u2f"}, []string{"u2f"}, nil, false)
			profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{}}, "", origin), "default", nil, []string{"password", "u2f"}, []string{"password", "u2f"}, nil, true)
			if reset := profileAuthChallengePersisted(t, store, "alice"); len(reset.AuthChallengeRules) != 0 || reset.CredentialVersion != after.CredentialVersion+1 {
				t.Fatal("reset did not persist defaults and revoke the previous login")
			}
			profileSessionRequireFreshLogin(t, f)
			token = authenticationChallengeLogin(t, f, "html", []string{"password", "u2f"}, key, credentialID)
			if claims := loginIdentityClaims(t, f, token, wantSubject); fmt.Sprint(claims["amr"]) != "[pwd hwk]" {
				t.Fatal("reset did not restore both backend checkpoints")
			}
			profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", fetch, "", origin), "default", nil, []string{"password", "u2f"}, []string{"password", "u2f"}, nil, false)
		})
	}
}

func TestE2EProfileAuthenticationFlowRejections(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, false, false, false, "")
	request := map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{"password"}}
	unauthenticated := replacementClientWithoutJar(f)
	oidcE2EStatus(t, unauthenticated.jsonRequest(t, "/api/profile", request, ""), http.StatusForbidden)
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	before := profileAuthChallengePersisted(t, store, "alice")
	for _, tc := range []struct {
		name       string
		challenges any
	}{
		{"null", nil}, {"scalar", "password"}, {"mixed", []any{"password", true}},
		{"empty rule", []string{""}}, {"unknown", []string{"sms"}},
		{"no eligible rule", []string{"u2f"}}, {"missing TOTP", []string{"password totp"}},
		{"missing MFA", []string{"mfa"}}, {"email", []string{"email"}},
		{"condition email", []string{"password if email not available"}},
		{"duplicate", []string{"password", "password"}}, {"incomplete OR", []string{"password or"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oidcE2EStatus(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": tc.challenges}, "", http.Header{"Origin": {f.server.URL}}), http.StatusBadRequest)
		})
	}
	oidcE2EStatus(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "overwrite_user_auth_challenges"}, ""), http.StatusBadRequest)
	oidcE2EStatus(t, f.jsonRequest(t, "/api/profile", request, "", http.Header{"Origin": {"https://untrusted.example.test"}, "Sec-Fetch-Site": {"same-site"}}), http.StatusForbidden)
	oidcE2EStatus(t, f.jsonRequest(t, "/api/profile", request, "", http.Header{"Origin": {f.server.URL}, "Content-Type": {"text/plain"}}), http.StatusUnsupportedMediaType)
	after := profileAuthChallengePersisted(t, store, "alice")
	if after.CredentialVersion != before.CredentialVersion || len(after.AuthChallengeRules) != 0 {
		t.Fatal("rejected request changed persisted rules or revoked the valid session")
	}
	profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "fetch_user_auth_challenges"}, ""), "default", nil, []string{"password"}, []string{"password"}, nil, false)
}

func TestE2EProfileAuthenticationFlowPortalPrecedence(t *testing.T) {
	f, store, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", authenticationChallengeConfig(t, []string{"require auth challenges u2f", "require password"}))
	portalURL, _ := url.Parse(f.server.URL)
	registration, key, credentialID := webAuthnE2ERegistration(t, portalURL.Hostname())
	if err := store.Request(operator.AddMfaToken, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "portal requirement"}, WebAuthn: registration}); err != nil {
		t.Fatal(err)
	}
	authenticationChallengeLogin(t, f, "html", []string{"u2f", "password"}, key, credentialID)
	profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{"password"}}, ""), "portal", []string{"password"}, []string{"password", "u2f"}, []string{"u2f", "password"}, []string{"password"}, true)
	profileSessionRequireFreshLogin(t, f)
	token := authenticationChallengeLogin(t, f, "html", []string{"u2f", "password"}, key, credentialID)
	if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[hwk pwd]" {
		t.Fatal("user preference bypassed mandatory portal factors")
	}
	profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "fetch_user_auth_challenges"}, ""), "portal", []string{"password"}, []string{"password", "u2f"}, []string{"u2f", "password"}, []string{"password"}, false)
}

func TestE2EProfileAuthenticationFlowConditionalTOTP(t *testing.T) {
	f, store, _ := newLoginIdentityE2E(t, false, false, true, "")
	// Provision a password preference so the first TOTP is used only after the
	// profile change. Never reuse a TOTP counter to make the journey pass.
	if err := store.Request(operator.OverwriteAuthChallengeRules, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Challenges: []string{"password"}}}); err != nil {
		t.Fatal(err)
	}
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	rules := []string{"u2f", "password totp if u2f not available", "password if u2f and totp not available"}
	profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": rules}, ""), "user", rules, []string{"password", "totp"}, []string{"password", "totp"}, nil, true)
	profileSessionRequireFreshLogin(t, f)
	token := authenticationChallengeLogin(t, f, "html", []string{"password", "totp"}, nil, "")
	if claims := loginIdentityClaims(t, f, token, "alice"); fmt.Sprint(claims["amr"]) != "[pwd otp]" {
		t.Fatal("saved conditional policy did not require the available TOTP")
	}
	profileAuthChallengeResponse(t, f.jsonRequest(t, "/api/profile", map[string]any{"kind": "fetch_user_auth_challenges"}, ""), "user", rules, []string{"password", "totp"}, []string{"password", "totp"}, nil, false)
}
