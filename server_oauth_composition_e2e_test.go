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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EServerUpstreamOAuthTrustComposition(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var failure, callback string
	var authorization url.Values
	var upstream *httptest.Server
	sign := func(claims map[string]any) string {
		header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "upstream", "typ": "JWT"})
		payload, _ := json.Marshal(claims)
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
	}
	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": upstream.URL, "authorization_endpoint": upstream.URL + "/authorize", "token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"EdDSA"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "upstream", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(public)}}})
		case "/authorize":
			authorization = r.URL.Query()
			if authorization.Get("redirect_uri") != callback || authorization.Get("client_id") != "upstream-client" || authorization.Get("code_challenge_method") != "S256" || authorization.Get("state") == "" || authorization.Get("nonce") == "" {
				t.Error("invalid upstream authorization")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, callback+"?"+url.Values{"code": {"single-code"}, "state": {authorization.Get("state")}}.Encode(), http.StatusFound)
		case "/token":
			if r.ParseForm() != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if authorization == nil || r.Form.Get("code") != "single-code" || r.Form.Get("client_id") != "upstream-client" || r.Form.Get("client_secret") != "synthetic-upstream-secret" || r.Form.Get("redirect_uri") != callback || r.Form.Get("state") != authorization.Get("state") || base64.RawURLEncoding.EncodeToString(challenge[:]) != authorization.Get("code_challenge") {
				t.Error("upstream exchange binding failed")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			idClaims := map[string]any{"iss": upstream.URL, "aud": "upstream-client", "sub": "external-user", "email": "external@example.test", "name": "External User", "nonce": authorization.Get("nonce"), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"authp/user"}}
			accessClaims := map[string]any{"iss": upstream.URL, "aud": "resource-api", "azp": "upstream-client", "roles": []string{"resource/editor"}, "exp": time.Now().Add(time.Hour).Unix()}
			switch failure {
			case "identity issuer":
				idClaims["iss"] = "https://untrusted.example.test"
			case "access issuer":
				accessClaims["iss"] = "https://untrusted.example.test"
			case "access audience":
				accessClaims["aud"] = "another-api"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": sign(idClaims), "access_token": sign(accessClaims), "token_type": "Bearer", "expires_in": 3600})
			authorization = nil
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	f := newServerCompositionFixture(t, true, func(cfg *authcrunch.Config) {
		lines := [][]string{{"realm", "upstream"}, {"driver", "generic"}, {"client_id", "upstream-client"}, {"client_secret", "synthetic-upstream-secret"}, {"base_auth_url", upstream.URL}, {"metadata_url", upstream.URL + "/.well-known/openid-configuration"}, {"issuer", upstream.URL}, {"access", "token", "audience", "resource-api"}, {"tls", "verification", "disabled"}}
		var encoded []string
		for _, line := range lines {
			encoded = append(encoded, cfgutil.EncodeArgs(line))
		}
		provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", encoded)
		if err != nil {
			t.Fatal(err)
		}
		cfg.IdentityProviders = append(cfg.IdentityProviders, provider)
		cfg.AuthenticationPortals[0].IdentityProviders = []string{"upstream"}
	})
	mu.Lock()
	callback = f.issuer + "/oauth2/upstream/authorization-code-callback"
	mu.Unlock()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	pool.AddCert(f.server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	defer transport.CloseIdleConnections()
	f.client.Transport = transport
	cookieConfig, err := cookieparser.NewCookieConfigFromDirectives(f.cookies)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "identity issuer", "access issuer", "access audience", "valid after rejections"} {
		t.Run(mode, func(t *testing.T) {
			mu.Lock()
			failure = mode
			mu.Unlock()
			f.client.Jar, _ = cookiejar.New(nil)
			location := f.issuer + "/oauth2/upstream"
			var result compositionResponse
			for step := range 3 {
				result = f.request(t, http.MethodGet, location, "", nil)
				if step < 2 {
					compositionStatus(t, result, http.StatusFound)
					location = result.header.Get("Location")
				}
			}
			if mode != "identity issuer" {
				compositionStatus(t, result, http.StatusSeeOther)
				// Independent portal-JWKS verification proves the upstream assertion
				// became a separately signed portal credential, with the right subject.
				var token string
				u, _ := url.Parse(f.issuer + "/portal")
				for _, c := range f.client.Jar.Cookies(u) {
					if c.Name == cookieConfig.AccessTokenCookieName {
						token = c.Value
					}
				}
				claims := f.verify(t, token, "/.well-known/jwks.json")
				if claims["sub"] != "external-user" {
					t.Fatal("upstream identity changed")
				}
				var supplemental bool
				for _, role := range claims["roles"].([]any) {
					if role == "resource/editor" {
						supplemental = true
					}
				}
				if supplemental != (mode == "valid" || mode == "valid after rejections") {
					t.Fatal("access-token trust settings did not control supplemental claims")
				}
				compositionStatus(t, f.request(t, http.MethodGet, f.origin+"/protected", "", http.Header{"Authorization": {"Bearer " + token}}), http.StatusNoContent)
			} else {
				if result.status == http.StatusSeeOther || result.header.Get("Authorization") != "" {
					t.Fatal("untrusted upstream claims authenticated")
				}
				u, _ := url.Parse(f.issuer + "/portal")
				for _, c := range f.client.Jar.Cookies(u) {
					if c.Name == cookieConfig.AccessTokenCookieName && c.Value != "" {
						t.Fatal("untrusted upstream issued portal cookie")
					}
				}
			}
		})
	}
}
