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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/translate"
	"go.uber.org/zap"
)

func TestI18NPortalDefaults(t *testing.T) {
	for _, tc := range []struct{ language, code, title, description string }{
		{"", "en", "Authentication Portal", "Performs user authentication."},
		{"French", "fr", "Portail d’authentification", "Authentifie les utilisateurs."},
		{"ar", "ar", "بوابة المصادقة", "يُجري مصادقة المستخدمين."},
	} {
		t.Run(tc.code, func(t *testing.T) {
			p := &Portal{config: &PortalConfig{Name: "localized", UI: &ui.Parameters{Language: tc.language}}, logger: zap.NewNop()}
			if err := p.configureUserInterface(); err != nil {
				t.Fatal(err)
			}
			args := p.ui.GetArgs()
			if args.LanguageCode() != tc.code || args.MetaTitle != tc.title || args.LogoDescription != tc.title || args.MetaDescription != tc.description {
				t.Fatal("default metadata did not follow the portal language")
			}
			if args.PageTitle != args.Translate("sign_in") {
				t.Fatal("default login title did not follow the portal language")
			}
		})
	}
	p := &Portal{config: &PortalConfig{Name: "custom", UI: &ui.Parameters{Language: "fr", Title: "My login", MetaTitle: "My portal", MetaDescription: "My description", LogoURL: "/custom.svg", LogoDescription: "My logo"}}, logger: zap.NewNop()}
	if err := p.configureUserInterface(); err != nil {
		t.Fatal(err)
	}
	args := p.ui.GetArgs()
	if args.PageTitle != "My login" || args.MetaTitle != "My portal" || args.MetaDescription != "My description" || args.LogoURL != "/custom.svg" || args.LogoDescription != "My logo" {
		t.Fatal("operator-authored branding was replaced")
	}
	p.config.UI.Language = "unsupported"
	if err := p.configureUserInterface(); err == nil {
		t.Fatal("unsupported configured language was accepted")
	}
}

func TestI18NHTTPErrorPages(t *testing.T) {
	for _, lang := range []string{"en", "de", "fr", "ja", "zh", "he", "ar", "ru"} {
		p := &Portal{config: &PortalConfig{Name: "localized", UI: &ui.Parameters{Language: lang}}, logger: zap.NewNop()}
		if err := p.configureUserInterface(); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			status int
			id     string
		}{
			{400, "bad_request_title"}, {401, "unauthorized_title"},
			{403, "access_denied_message"}, {404, "page_not_found_message"},
			{405, "method_not_allowed_title"}, {429, "too_many_requests_title"},
			{500, "internal_server_error_message"}, {501, "not_implemented_title"},
			{502, "bad_gateway_title"}, {503, "service_unavailable_title"},
			{418, "request_failed_title"},
		} {
			t.Run(lang+"/"+strconv.Itoa(tc.status), func(t *testing.T) {
				rr := requests.NewRequest()
				rr.Upstream.BasePath = "/tenant/auth"
				request := httptest.NewRequest(http.MethodGet, "https://example.test/tenant/auth/register", nil)
				recorder := httptest.NewRecorder()
				if err := p.handleHTTPError(t.Context(), recorder, request, rr, tc.status); err != nil {
					t.Fatal(err)
				}
				if recorder.Code != tc.status || recorder.Header().Get("Content-Type") != "text/html; charset=utf-8" || recorder.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("localization changed error status, media type or cache policy")
				}
				title := translate.Translate(tc.id, translate.LangID(lang), nil)
				if title == tc.id || !strings.Contains(recorder.Body.String(), `<h1 id="generic-title">`+title+`</h1>`) {
					t.Fatal("HTTP error heading did not follow the portal language")
				}
				if !strings.Contains(recorder.Body.String(), `<title>`+p.ui.MetaTitle+" - "+title+`</title>`) {
					t.Fatal("document title differs from the error heading")
				}
			})
		}
	}
}
