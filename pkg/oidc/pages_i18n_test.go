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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/translate"
)

func TestOIDCLocalizedPages(t *testing.T) {
	for _, tc := range []struct {
		lang                                translate.LangID
		code, dir, title, permission, claim string
	}{
		{translate.French, "fr", "ltr", "Autoriser l’application", "Identifiant du compte", "Heure de connexion"},
		{translate.Arabic, "ar", "rtl", "تفويض التطبيق", "معرّف الحساب", "وقت تسجيل الدخول"},
		{"unsupported", "en", "ltr", "Authorize application", "Account identifier", "Sign-in time"},
	} {
		t.Run(string(tc.lang), func(t *testing.T) {
			config := oidcTestConfig()
			config.Clients[0].SkipConsent = false
			config.Clients[0].Scopes = []string{"openid", "profile", "email", "address", "phone", "offline_access"}
			verifier := &unitIdentityVerifier{enabled: true}
			provider, err := NewProvider(config, verifier, Options{Language: tc.lang})
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			f := &providerFixture{provider: provider, config: config, verifier: verifier}
			cookie := responseCookie(t, f.login(t), provider.sessionCookie)
			params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid profile email address phone offline_access"}, "prompt": {"consent"}, "claims": {`{"userinfo":{"auth_time":null},"id_token":{"given_name":null}}`}}
			response := oidcUnitRequest(t, f, "GET", "/oidc/authorize?"+params.Encode(), nil, cookie)
			if response.Code != 200 {
				t.Fatal("missing consent")
			}
			body := response.Body.String()
			for _, value := range []string{tc.title, tc.permission, tc.claim, `lang="` + tc.code + `"`, `dir="` + tc.dir + `"`, `value="allow"`, `value="deny"`} {
				if !strings.Contains(body, value) {
					t.Errorf("missing %q", value)
				}
			}
			for _, scope := range oidcScopeClaims {
				for _, name := range scope {
					if localizedOIDCClaimLabel(name, tc.lang) == name {
						t.Errorf("untranslated claim %s", name)
					}
				}
			}
			if localizedOIDCClaimLabel("custom_claim", tc.lang) != "custom_claim" {
				t.Fatal("extension claim identifier changed")
			}
			request := httptest.NewRequest("GET", oidcTestOrigin+"/auth/oidc/authorize", nil)
			request.Header.Set("Accept", "text/html")
			recorder := httptest.NewRecorder()
			provider.ServeHTTP(recorder, request)
			if recorder.Code < 400 || !strings.Contains(recorder.Body.String(), provider.translate("oidc_invalid_request")) {
				t.Fatal("browser error lost localization or status")
			}
			if strings.Contains(recorder.Body.String(), "<form") {
				t.Fatal("invalid request exposed a form")
			}
		})
	}
}
