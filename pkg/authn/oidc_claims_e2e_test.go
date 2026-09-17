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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

func oidcClaimsFixture(t *testing.T) (*oidcE2EFixture, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyN := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	f := newOIDCE2EFixtureConfigured(t, "/auth", false, []string{"realms local", "signing key files ../../testdata/rskeys/test_2_pri.pem", "applications consenting-web trusted-web post-web browser-app", "acr urn:authcrunch:password pwd", "refresh lifetime 600", "max refresh tokens 16"}, func(path string, apps map[string]*oidc.ClientConfig) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var db identity.Database
		if json.Unmarshal(data, &db) != nil {
			t.Fatal("decode fixture identity")
		}
		for _, u := range db.Users {
			if u.Username == "alice" {
				u.Name = &identity.Name{First: "Alice", Last: "Example"}
				u.Profile = &identity.Profile{GivenName: "Alice", FamilyName: "Example", MiddleName: "Test", Nickname: "Al", ProfileURL: "https://example.test/alice", Picture: "https://example.test/alice.png", Website: "https://example.test", Gender: "unspecified", Birthdate: "2000-01-01", Zoneinfo: "America/New_York", Locale: "en-US", UpdatedAt: 1700000000, PhoneNumber: "+1 202-555-0100", PhoneNumberVerified: new(false), Address: &identity.Address{Formatted: "1 Example Street, Testville", StreetAddress: "1 Example Street", Locality: "Testville", Region: "Test", PostalCode: "00000", Country: "US"}}
			}
		}
		data, err = json.Marshal(&db)
		if err != nil {
			t.Fatal(err)
		}
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("persist fixture attributes")
		}
		client, err := oidcparser.NewOIDCClientConfigFromDirectives("consenting-web", []string{"client_id basic", "client_secret " + oidcE2ESecret, "redirect_uri https://rp.example.test/callback?registered=yes", "scopes openid profile email address phone offline_access", "request_object_key client-key " + keyN + " AQAB", "request_object_signing_alg RS256"})
		if err != nil {
			t.Fatal(err)
		}
		apps["consenting-web"] = client
	})
	return f, key
}
func oidcClaimsTokens(t *testing.T, r oidcE2EResponse) map[string]any {
	t.Helper()
	oidcE2EStatus(t, r, 200)
	var result map[string]any
	if json.Unmarshal(r.body, &result) != nil {
		t.Fatal("invalid token JSON")
	}
	return result
}
func TestE2EOIDCClaimsAndRefresh(t *testing.T) {
	f, _ := oidcClaimsFixture(t)
	f.loginBrowser(t)
	params := f.authorization("basic")
	params.Set("scope", "openid")
	params.Set("claims", `{"userinfo":{"name":{"essential":true}},"id_token":{"given_name":null,"acr":{"essential":true,"values":["urn:authcrunch:password"]}}}`)
	consent := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	if !strings.Contains(string(consent.body), "Full name") || !strings.Contains(string(consent.body), "Given name") {
		t.Fatal("claim consent missing")
	}
	code := oidcProviderE2ECode(t, f.approve(t, consent, "allow"))
	tokens := oidcE2ETokens(t, f.exchange(t, "basic", code, oidcE2EVerifier))
	id := f.verifyIDToken(t, tokens, "basic")
	if id["given_name"] != "Alice" || id["name"] != nil || id["acr"] != "urn:authcrunch:password" {
		t.Fatal("ID claims not bound to request and authentication")
	}
	info := oidcClaimsTokens(t, f.request(t, "POST", "/oidc/userinfo", url.Values{"access_token": {tokens["access_token"].(string)}}, nil))
	if len(info) != 2 || info["name"] != "Example, Alice" {
		t.Fatal("essential name missing or other claims leaked")
	}
	params.Set("claims", `{"id_token":{"acr":{"essential":true,"value":"urn:unearned:mfa"}}}`)
	params.Set("prompt", "none")
	denied := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	target, _ := url.Parse(denied.header.Get("Location"))
	if target.Query().Get("error") != "access_denied" {
		t.Fatal("unearned ACR accepted")
	}
	params.Del("claims")
	params.Set("scope", "openid profile email address phone offline_access")
	params.Set("prompt", "consent")
	consent = f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	if !strings.Contains(string(consent.body), "Continued access") || !strings.Contains(string(consent.body), "postal address") {
		t.Fatal("expanded consent missing")
	}
	code = oidcProviderE2ECode(t, f.approve(t, consent, "allow"))
	tokens = oidcClaimsTokens(t, f.exchange(t, "basic", code, oidcE2EVerifier))
	firstID := f.verifyIDToken(t, tokens, "basic")
	info = oidcClaimsTokens(t, f.request(t, "POST", "/oidc/userinfo", url.Values{"access_token": {tokens["access_token"].(string)}}, nil))
	for _, name := range []string{"name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at", "email", "email_verified", "phone_number", "phone_number_verified", "address"} {
		if _, ok := info[name]; !ok {
			t.Fatalf("missing scoped claim %s", name)
		}
	}
	if info["phone_number_verified"] != false || info["email_verified"] != false {
		t.Fatal("unverified attribute represented as verified")
	}
	old := tokens["refresh_token"].(string)
	headers := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("basic:"+oidcE2ESecret))}}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {old}}
	refreshed := oidcClaimsTokens(t, f.request(t, "POST", "/oidc/token", form, headers))
	freshID := f.verifyIDToken(t, refreshed, "basic")
	if firstID["auth_time"] != freshID["auth_time"] || firstID["sub"] != freshID["sub"] || refreshed["refresh_token"] == old {
		t.Fatal("refresh changed authentication or did not rotate")
	}
	oidcE2EError(t, f.request(t, "POST", "/oidc/token", form, headers), "invalid_grant")
	form.Set("refresh_token", refreshed["refresh_token"].(string))
	oidcE2EError(t, f.request(t, "POST", "/oidc/token", form, headers), "invalid_grant")
	oidcE2EStatus(t, f.request(t, "POST", "/oidc/userinfo", url.Values{"access_token": {refreshed["access_token"].(string)}}, nil), 401)
}
func TestE2EOIDCSignedRequestObject(t *testing.T) {
	f, key := oidcClaimsFixture(t)
	f.loginBrowser(t)
	params := f.authorization("basic")
	inner := map[string]any{"iss": "basic", "aud": f.issuer, "client_id": "basic", "response_type": "code", "redirect_uri": f.callback, "scope": "openid profile", "nonce": params.Get("nonce"), "state": params.Get("state"), "code_challenge": oidcE2EChallenge, "code_challenge_method": "S256"}
	data, _ := json.Marshal(inner)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"client-key"}`))
	payload := header + "." + base64.RawURLEncoding.EncodeToString(data)
	digest := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	params.Set("request", payload+"."+base64.RawURLEncoding.EncodeToString(signature))
	consent := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	code := oidcProviderE2ECode(t, f.approve(t, consent, "allow"))
	tokens := oidcE2ETokens(t, f.exchange(t, "basic", code, oidcE2EVerifier))
	f.verifyIDToken(t, tokens, "basic")
	signature[0] ^= 1
	params.Set("request", payload+"."+base64.RawURLEncoding.EncodeToString(signature))
	response := f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil)
	target, _ := url.Parse(response.header.Get("Location"))
	if target.Query().Get("error") != "invalid_request_object" {
		t.Fatal("tampered Request Object accepted")
	}
}

func TestE2EOIDCRefreshRevocation(t *testing.T) {
	for _, operation := range []string{"revoke", "logout", "disable", "reset_password", "overwrite_auth_challenges", "reload"} {
		t.Run(operation, func(t *testing.T) {
			f, _ := oidcClaimsFixture(t)
			adminHTTP := *f.client
			adminHTTP.Jar = nil
			management := *f
			management.client = &adminHTTP
			admin, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", Username: "admin", Password: tests.TestPwd1}, authclient.Options{HTTPClient: &adminHTTP})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := admin.Authenticate(t.Context())
			if err != nil {
				t.Fatal("administrator login failed")
			}
			f.loginBrowser(t)
			params := f.authorization("basic")
			params.Set("scope", "openid offline_access")
			params.Set("prompt", "consent")
			code := oidcProviderE2ECode(t, f.approve(t, f.request(t, "GET", "/oidc/authorize?"+params.Encode(), nil, nil), "allow"))
			tokens := oidcClaimsTokens(t, f.exchange(t, "basic", code, oidcE2EVerifier))
			headers := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("basic:"+oidcE2ESecret))}}
			switch operation {
			case "revoke":
				oidcE2EStatus(t, f.request(t, "POST", "/oidc/revoke", url.Values{"token": {tokens["refresh_token"].(string)}}, headers), 200)
			case "logout":
				f.request(t, "GET", "/logout", nil, nil)
			case "reload":
				oidcE2EStatus(t, management.jsonRequest(t, "/api/server/reload", map[string]any{"realm": "local"}, credentials.AccessToken), 200)
			default:
				response := management.jsonRequest(t, "/api/server/user", map[string]any{"realm": "local", "operation": operation, "user": map[string]any{"username": "alice", "email": "alice@example.test", "challenges": []string{"password", "totp"}}}, credentials.AccessToken)
				oidcE2EStatus(t, response, 200)
				var result map[string]any
				if json.Unmarshal(response.body, &result) != nil || result["status"] != "success" {
					t.Fatal("security mutation failed")
				}
			}
			oidcE2EError(t, f.request(t, "POST", "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}, headers), "invalid_grant")
			oidcE2EStatus(t, f.request(t, "POST", "/oidc/userinfo", url.Values{"access_token": {tokens["access_token"].(string)}}, nil), 401)
		})
	}
}
