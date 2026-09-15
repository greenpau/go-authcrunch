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

package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EStandaloneNativeLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", host+":0")
			if err != nil {
				t.Fatal("native loopback listener unavailable", err)
			}
			received := make(chan url.Values, 1)
			callback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/callback" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				select {
				case received <- r.URL.Query():
				default:
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			callback.Listener.Close()
			callback.Listener = listener
			callback.Start()
			t.Cleanup(callback.Close)
			actual := callback.URL + "/callback?registered=yes"
			registered := "http://" + host + ":1/callback?registered=yes"
			server := httptest.NewUnstartedServer(nil)
			t.Cleanup(server.Close)
			origin := "https://" + server.Listener.Addr().String()
			issuer := origin + "/auth"
			registration, err := oidcparser.NewOIDCClientConfigFromDirectives("native", []string{"client_id native", "token_endpoint_auth_method none", "skip_consent true", cfgutil.EncodeArgs([]string{"redirect_uri", registered})})
			if err != nil {
				t.Fatal(err)
			}
			config, err := oidcparser.NewOIDCProviderConfigFromDirectives([]string{"issuer " + issuer, "realms employees", "signing key files ../../testdata/rskeys/test_2_pri.pem", "applications desktop"}, map[string]*oidc.ClientConfig{"desktop": registration})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var restored oidc.Config
			if json.Unmarshal(encoded, &restored) != nil {
				t.Fatal("could not restore provider registration")
			}
			verifier := &standaloneIdentityVerifier{}
			provider, err := oidc.NewProvider(&restored, verifier, oidc.Options{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/auth/login" {
					provider.ServeHTTP(w, r)
					return
				}
				if r.Method != http.MethodPost {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if !provider.ValidateLoginRequest(w, r) {
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 4096)
				if r.ParseForm() != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				proof, err := verifier.authenticate(r.PostForm.Get("username"), r.PostForm.Get("password"))
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if provider.CompleteLogin(r.Context(), w, r, proof) != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
			server.StartTLS()
			client := server.Client()
			client.Timeout = 5 * time.Second
			client.Jar, _ = cookiejar.New(nil)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			request := func(method, path string, form url.Values, headers http.Header) standaloneResponse {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), method, issuer+path, strings.NewReader(form.Encode()))
				if err != nil {
					t.Fatal("could not construct provider request")
				}
				r.Header = headers.Clone()
				if r.Header == nil {
					r.Header = make(http.Header)
				}
				if method == http.MethodPost {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal("provider request failed")
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				if err != nil {
					t.Fatal("provider response failed")
				}
				return standaloneResponse{status: response.StatusCode, header: response.Header, body: body}
			}
			login := request(http.MethodPost, "/login", url.Values{"username": {"alice"}, "password": {"standalone-test-password"}}, http.Header{"Origin": {origin}})
			if login.status != http.StatusNoContent {
				t.Fatal("standalone authentication failed")
			}
			proof := strings.Repeat("v", 43)
			sum := sha256.Sum256([]byte(proof))
			params := url.Values{"client_id": {"native"}, "redirect_uri": {actual}, "response_type": {"code"}, "scope": {"openid email"}, "state": {"native-state"}, "nonce": {"standalone-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
			for _, wrong := range []string{strings.Replace(actual, "/callback", "/other", 1), actual + "&extra=yes", "http://localhost:43112/callback?registered=yes"} {
				params.Set("redirect_uri", wrong)
				denied := request(http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, nil)
				if denied.status != http.StatusBadRequest || denied.header.Get("Location") != "" {
					t.Fatal("unregistered callback received a redirect")
				}
			}
			params.Set("redirect_uri", actual)
			authorized := request(http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, nil)
			target, err := url.Parse(authorized.header.Get("Location"))
			endpoint, _ := url.Parse(actual)
			if err != nil || authorized.status != http.StatusFound || target.Scheme != endpoint.Scheme || target.Host != endpoint.Host || target.Path != endpoint.Path {
				t.Fatal("authorization did not target actual native listener")
			}
			// Deliver the actual authorization response over TCP to the native app.
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.String(), nil)
			if err != nil {
				t.Fatal("could not construct native callback")
			}
			native := &http.Client{Timeout: 5 * time.Second}
			response, err := native.Do(r)
			if err != nil {
				t.Fatal("native listener did not receive authorization")
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatal("native callback rejected")
			}
			var values url.Values
			select {
			case values = <-received:
			case <-t.Context().Done():
				t.Fatal("native callback missing")
			}
			if values.Get("state") != "native-state" || values.Get("iss") != issuer || values.Get("registered") != "yes" || values.Get("code") == "" {
				t.Fatal("native callback lost authorization binding")
			}
			form := url.Values{"client_id": {"native"}, "grant_type": {"authorization_code"}, "code": {values.Get("code")}, "redirect_uri": {registered}, "code_verifier": {proof}}
			if result := request(http.MethodPost, "/oidc/token", form, nil); result.status != http.StatusBadRequest {
				t.Fatal("registered placeholder port redeemed actual authorization")
			}
			form.Set("redirect_uri", actual)
			result := request(http.MethodPost, "/oidc/token", form, nil)
			var tokens map[string]any
			if result.status != http.StatusOK || json.Unmarshal(result.body, &tokens) != nil {
				t.Fatal("native PKCE exchange failed")
			}
			jwks := request(http.MethodGet, "/oidc/jwks", nil, nil)
			claims := verifyStandaloneIDToken(t, tokens["id_token"].(string), jwks.body, issuer, "native")
			info := request(http.MethodGet, "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
			var identity map[string]any
			if info.status != http.StatusOK || json.Unmarshal(info.body, &identity) != nil || identity["sub"] != claims["sub"] || identity["email"] != "alice@example.test" {
				t.Fatal("native token did not authorize the authenticated identity")
			}
		})
	}
}
