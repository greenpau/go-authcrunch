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

package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
)

func TestOIDCClaimsValidation(t *testing.T) {
	client := oidcTestConfig().Clients[0]
	if err := client.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `[]`, `{"userinfo":null}`, `{"userinfo":{"name":true}}`, `{"userinfo":{"name":{"essential":null}}}`, `{"userinfo":{"name":{"essential":"true"}}}`, `{"userinfo":{"name":{"value":"a","values":["b"]}}}`, `{"userinfo":{"name":{"values":[]}}}`, `{"userinfo":{"name":null,"name":null}}`, `{"id_token":{"acr":{"values":[1]}}}`, `{"id_token":{"sub":{"value":null}}}`} {
		if result, err := parseOIDCClaims(raw, client); err == nil || result != nil {
			t.Fatalf("accepted malformed claims %s", raw)
		}
	}
	claims, err := parseOIDCClaims(`{"userinfo":{"name":{"essential":true},"phone_number":null,"admin":null},"id_token":{"email":null}}`, client)
	if err != nil || len(claims["userinfo"]) != 1 || !claims["userinfo"]["name"].essential || len(claims["id_token"]) != 1 {
		t.Fatal("claims escaped registered permissions")
	}
	r := &oidcAuthorization{scopes: []string{"openid"}, claims: claims}
	current := oidcCurrentClaims(Identity{Username: "alice", Name: "Alice", Email: "a@example.test", Profile: &identity.Profile{GivenName: "Alice", PhoneNumberVerified: new(true)}}, "stable")
	info := map[string]any{"sub": "stable"}
	oidcDisclose(info, current, r, "userinfo")
	if len(info) != 2 || info["name"] != "Alice" {
		t.Fatal("individual claim incorrectly scoped")
	}
	id := map[string]any{"sub": "stable"}
	oidcDisclose(id, current, r, "id_token")
	if len(id) != 2 || id["email"] != "a@example.test" {
		t.Fatal("claim location ignored")
	}
	if _, ok := current["phone_number_verified"]; ok {
		t.Fatal("verification without a number")
	}
}

func TestOIDCAuthenticationContext(t *testing.T) {
	o := &Provider{config: Config{AuthenticationContexts: []AuthenticationContext{{Value: "urn:test:password", Methods: []string{"pwd"}}, {Value: "urn:test:mfa", Methods: []string{"pwd", "otp"}}}}}
	s := &oidcSession{subject: "alice", methods: []string{"pwd"}}
	for _, tc := range []struct {
		raw     string
		allowed bool
	}{
		{`{"id_token":{"acr":{"essential":true,"values":["urn:test:password"]}}}`, true},
		{`{"id_token":{"acr":{"essential":true,"value":"urn:test:mfa"}}}`, false},
		{`{"id_token":{"acr":{"value":"urn:test:mfa"}}}`, true},
		{`{"id_token":{"sub":{"value":"mallory"}}}`, false},
		{`{"userinfo":{"sub":{"values":["alice"]}}}`, true},
	} {
		claims, err := parseOIDCClaims(tc.raw, &ClientConfig{})
		if err != nil {
			t.Fatal(err)
		}
		r := &oidcAuthorization{claims: claims, acrValues: []string{"urn:test:mfa"}}
		if o.satisfiesClaims(s, r) != tc.allowed || o.authenticationContext(s, r) != "urn:test:password" {
			t.Fatal("requested ACR substituted for actual authentication")
		}
	}
	if err := validateAuthenticationContexts([]AuthenticationContext{{Value: "x", Methods: []string{"invented"}}}); err == nil {
		t.Fatal("unknown authentication method accepted")
	}
}

func TestOIDCIndividualClaimConsent(t *testing.T) {
	f := newProviderFixture(t)
	o := f.provider
	o.clients["client"].SkipConsent = false
	cookie := responseCookie(t, f.login(t), o.sessionCookie)
	params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "claims": {`{"userinfo":{"name":{"essential":true}}}`}}
	response := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Full name") {
		t.Fatal("individual claim missing from consent")
	}
	// Previously approved openid alone cannot authorize the additional name.
	s := o.sessions[oidcCookieHash(responseRequest(cookie), o.sessionCookie)]
	s.consents = map[string][]string{"client": {"openid"}}
	params.Set("prompt", "none")
	denied := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, cookie)
	u, _ := url.Parse(denied.Header().Get("Location"))
	if u.Query().Get("error") != "consent_required" {
		t.Fatal("individual claim bypassed consent")
	}
}
func responseRequest(cookie *http.Cookie) *http.Request {
	r, _ := http.NewRequest("GET", oidcTestOrigin, nil)
	r.AddCookie(cookie)
	return r
}

func TestOIDCProfileSerialization(t *testing.T) {
	profile := &identity.Profile{GivenName: "Alice", PhoneNumber: "+1 202 555 0100", PhoneNumberVerified: new(false), Address: &identity.Address{Locality: "Testville"}}
	clone := profile.Clone()
	clone.Address.Locality = "Changed"
	*clone.PhoneNumberVerified = true
	if profile.Address.Locality != "Testville" || *profile.PhoneNumberVerified {
		t.Fatal("profile clone aliases persistent identity")
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var restored identity.Profile
	if json.Unmarshal(data, &restored) != nil || restored.PhoneNumberVerified == nil || *restored.PhoneNumberVerified {
		t.Fatal("verification false was lost")
	}
}
