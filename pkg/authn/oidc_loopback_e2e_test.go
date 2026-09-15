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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EOIDCNativeLoopback(t *testing.T) {
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
			registration, err := oidcparser.NewOIDCClientConfigFromDirectives("native", []string{"client_id native", "token_endpoint_auth_method none", "skip_consent true", cfgutil.EncodeArgs([]string{"redirect_uri", registered})})
			if err != nil {
				t.Fatal(err)
			}
			f, _, _ := newLoginIdentityConfiguredE2E(t, false, true, false, "", func(cfg *authn.PortalConfig) {
				original := cfg.OIDCProvider
				provider, err := oidcparser.NewOIDCProviderConfigFromDirectives([]string{
					cfgutil.EncodeArgs([]string{"issuer", original.Issuer}), "realms local",
					cfgutil.EncodeArgs(append([]string{"signing", "key", "files"}, original.SigningKeyFiles...)), "applications desktop",
				}, map[string]*oidc.ClientConfig{"desktop": registration})
				if err != nil {
					t.Fatal(err)
				}
				cfg.OIDCProvider = provider
			})
			f.callback = actual
			f.loginBrowser(t)
			params := f.authorization("native")
			for _, wrong := range []string{strings.Replace(actual, "/callback", "/other", 1), actual + "&extra=yes", "http://localhost:43112/callback?registered=yes"} {
				params.Set("redirect_uri", wrong)
				denied := f.request(t, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, nil)
				oidcE2EStatus(t, denied, http.StatusBadRequest)
				if denied.header.Get("Location") != "" {
					t.Fatal("unregistered callback received a redirect")
				}
			}
			params.Set("redirect_uri", actual)
			response := f.request(t, http.MethodGet, "/oidc/authorize?"+params.Encode(), nil, nil)
			oidcE2EStatus(t, response, http.StatusFound)
			target, err := url.Parse(response.header.Get("Location"))
			endpoint, _ := url.Parse(actual)
			if err != nil || target.Scheme != endpoint.Scheme || target.Host != endpoint.Host || target.Path != endpoint.Path {
				t.Fatal("portal did not target actual native listener")
			}
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.String(), nil)
			if err != nil {
				t.Fatal("could not construct native callback")
			}
			native := &http.Client{Timeout: 5 * time.Second}
			delivered, err := native.Do(r)
			if err != nil {
				t.Fatal("native callback delivery failed")
			}
			delivered.Body.Close()
			if delivered.StatusCode != http.StatusNoContent {
				t.Fatal("native callback rejected")
			}
			var values url.Values
			select {
			case values = <-received:
			case <-t.Context().Done():
				t.Fatal("native callback missing")
			}
			if values.Get("state") != params.Get("state") || values.Get("iss") != f.issuer || values.Get("registered") != "yes" || values.Get("code") == "" {
				t.Fatal("callback lost protocol binding")
			}
			form := url.Values{"client_id": {"native"}, "grant_type": {"authorization_code"}, "code": {values.Get("code")}, "redirect_uri": {registered}, "code_verifier": {oidcE2EVerifier}}
			denied := f.request(t, http.MethodPost, "/oidc/token", form, nil)
			oidcE2EStatus(t, denied, http.StatusBadRequest)
			var failure map[string]string
			if json.Unmarshal(denied.body, &failure) != nil || failure["error"] != "invalid_grant" {
				t.Fatal("wrong callback port was not denied")
			}
			form.Set("redirect_uri", actual)
			tokens := oidcE2ETokens(t, f.request(t, http.MethodPost, "/oidc/token", form, nil))
			claims := f.verifyIDToken(t, tokens, "native")
			info := f.request(t, http.MethodGet, "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
			var identity map[string]any
			if info.status != http.StatusOK || json.Unmarshal(info.body, &identity) != nil || identity["sub"] != claims["sub"] || identity["email"] != "alice@example.test" {
				t.Fatal("native token did not authorize the authenticated local identity")
			}
		})
	}
}
