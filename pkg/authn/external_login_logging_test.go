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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type externalLoginEventProvider struct {
	externalLoginTestProvider
	code int
	err  error
}

func (p *externalLoginEventProvider) Request(_ operator.Type, r *requests.Request) error {
	r.Response.Code = p.code
	r.Response.RedirectURL = "https://issuer.example.test/authorize"
	r.Response.LoginState = strings.Repeat("A", 43)
	// Deliberately invalid subject reaches post-provider claim rejection. The
	// earlier event must retain its timing without reflecting this private data.
	r.Response.Payload = map[string]any{
		"sub": 17, "roles": []string{"authp/user"},
		"access_token": "external-event-access-secret",
		"profile":      map[string]any{"records": []any{map[string]any{"refresh_token": "external-event-nested-secret"}}},
	}
	return p.err
}

func TestExternalLoginEventMetadata(t *testing.T) {
	for _, method := range []string{"oauth2", "saml"} {
		for _, tc := range []struct {
			name               string
			code, status, logs int
			err                error
		}{
			{name: "provider accepted before claim rejection", code: http.StatusOK, status: http.StatusUnauthorized, logs: 1},
			{name: "authorization redirect", code: http.StatusFound, status: http.StatusFound},
			{name: "provider rejection", code: http.StatusOK, status: http.StatusUnauthorized, err: errors.New("synthetic provider rejection")},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				core, logs := observer.New(zap.InfoLevel)
				provider := &externalLoginEventProvider{code: tc.code, err: tc.err}
				portal, err := NewPortal(PortalParameters{
					Config: &PortalConfig{Name: "external-event", IdentityProviders: []string{"upstream"}, RawCryptoKeyStoreConfig: []string{"crypto key event sign-verify synthetic-external-event-signing-secret"}},
					Logger: zap.New(core), IdentityProviders: []idp.IdentityProvider{provider},
				})
				if err != nil {
					t.Fatal("construct external event portal")
				}
				t.Cleanup(portal.Close)
				r := httptest.NewRequest(http.MethodGet, "https://portal.example.test/auth/"+method+"/upstream", nil)
				r.RequestURI = r.URL.RequestURI()
				rr := requests.NewRequest()
				rr.ID, rr.Upstream.SessionID = "external-event-request", "external-event-session"
				rr.Upstream.Request, rr.Upstream.BaseURL, rr.Upstream.BasePath = r, "https://portal.example.test", "/auth/"
				w := httptest.NewRecorder()
				if err := portal.handleHTTPExternalLogin(t.Context(), w, r, rr, method); err != nil {
					t.Fatal("external event handler failed")
				}
				if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("external provider boundary returned HTTP %d, want %d", w.Code, tc.status)
				}
				entries := logs.FilterMessage("Successful login").All()
				if len(entries) != tc.logs {
					t.Fatalf("provider acceptance event count %d, want %d", len(entries), tc.logs)
				}
				for _, entry := range entries {
					fields := entry.ContextMap()
					if entry.Level != zap.InfoLevel || fields["session_id"] != "external-event-session" || fields["request_id"] != "external-event-request" || fields["auth_method"] != method || fields["auth_realm"] != "upstream" {
						t.Fatal("provider event lost severity or its four correlation/routing fields")
					}
					if _, exists := fields["user"]; exists {
						t.Fatal("provider acceptance event reflected arbitrary identity data")
					}
				}
				assertAuthenticationEventSecrets(t, logs, "external-event-access-secret", "external-event-nested-secret")
				assertAuthenticationSuccessEvents(t, logs, 0)
				for _, c := range w.Result().Cookies() {
					if c.Name == portal.cookie.AccessTokenCookieName && c.Value != "" && c.MaxAge >= 0 {
						t.Fatal("provider boundary control delivered an access credential")
					}
				}
			})
		}
	}
}
