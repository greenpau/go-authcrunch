// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"context"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type customResponseWriter struct {
	body       []byte
	statusCode int
	header     http.Header
}

func buildCustomResponseWriter() *customResponseWriter {
	return &customResponseWriter{
		header: http.Header{},
	}
}

func (w *customResponseWriter) Header() http.Header {
	return w.header
}

func (w *customResponseWriter) Write(b []byte) (int, error) {
	w.body = b
	return 0, nil
}

func (w *customResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func TestInjectRedirectURL(t *testing.T) {

	t.Run("Strips login hint from redirect URL if present", func(t *testing.T) {
		reqURL := url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/myPage",
			RawQuery: "redirect_url=https%3A%2F%2Ffoo.bar%2Fredir%3Flogin_hint%3Dmy%40email.com",
		}
		r := http.Request{URL: &reqURL, Method: "GET"}
		f, _ := cookie.NewFactory(nil)
		p := Portal{
			config: &PortalConfig{
				Name: "somePortal",
			},
			logger: zap.L(),
			cookie: f,
		}
		request := requests.NewRequest()

		p.injectRedirectURL(context.Background(), buildCustomResponseWriter(), &r, request)

		cookieParts := strings.Split(request.Response.RedirectURL, ";")
		tests.EvalObjectsWithLog(t, "redirect url", "AUTHP_REDIRECT_URL=https://foo.bar/redir", cookieParts[0], []string{})
	})
}

func TestRefererSanitization(t *testing.T) {
	t.Run("should sanitize referral url if its malformed in a way that is intended to cause a XSS", func(t *testing.T) {
		reqURL := url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/myPage",
			RawQuery: "redirect_url=https%3A%2F%2Ffoo.bar%2Fredir",
		}
		r := http.Request{URL: &reqURL, Method: "GET"}
		r.Header = make(http.Header)
		maliciousURL := "https://www.google.com/search?hl=en&q=testing'\"()&%<acx><ScRiPt >alert(9854)</ScRiPt>"
		r.Header.Set("Referer", maliciousURL)
		f, _ := cookie.NewFactory(nil)
		uiFactory := ui.NewFactory()
		p := Portal{
			config: &PortalConfig{
				Name: "somePortal",
				UI: &ui.Parameters{
					Theme: "",
				},
			},
			logger: zap.L(),
			cookie: f,
			ui:     uiFactory,
		}
		_ = p.configureUserInterface()
		request := requests.NewRequest()
		rw := buildCustomResponseWriter()

		_ = p.handleHTTPError(context.Background(), rw, &r, request, 404)
		rb := string(rw.body)

		tests.EvalObjectsWithLog(t, "sanitized url", true, strings.Contains(rb, "https://www.google.com/search?hl=en%26q=testing%27%22()%26%%3Cacx%3E%3CScRiPt %3Ealert(9854)%3C/ScRiPt%3E"), []string{})
	})
}

func TestRefererSchemeValidation(t *testing.T) {
	buildPortal := func() *Portal {
		f, _ := cookie.NewFactory(nil)
		uiFactory := ui.NewFactory()
		p := &Portal{
			config: &PortalConfig{
				Name: "somePortal",
				UI: &ui.Parameters{
					Theme: "",
				},
			},
			logger: zap.L(),
			cookie: f,
			ui:     uiFactory,
		}
		_ = p.configureUserInterface()
		return p
	}

	var testcases = []struct {
		name    string
		referer string
		want    string
	}{
		{
			name:    "rejects javascript protocol in Referer",
			referer: "javascript:alert(document.domain)",
			want:    "/",
		},
		{
			name:    "rejects uppercase JAVASCRIPT protocol in Referer",
			referer: "JAVASCRIPT:alert(document.domain)",
			want:    "/",
		},
		{
			name:    "rejects data protocol in Referer",
			referer: "data:text/html,<script>alert(1)</script>",
			want:    "/",
		},
		{
			name:    "rejects javascript protocol disguised with path",
			referer: "javascript:alert(1)//https://example.com",
			want:    "/",
		},
		{
			name:    "allows valid https Referer",
			referer: "https://example.com/page",
			want:    "https://example.com/page",
		},
		{
			name:    "allows valid http Referer",
			referer: "http://example.com/page",
			want:    "http://example.com/page",
		},
		{
			name:    "rejects vbscript protocol in Referer",
			referer: "vbscript:MsgBox",
			want:    "/",
		},
		{
			name:    "rejects file protocol in Referer",
			referer: "file:///etc/passwd",
			want:    "/",
		},
		{
			name:    "falls back to / on malformed URL",
			referer: "://no-scheme",
			want:    "/",
		},
		{
			name:    "falls back to / when Referer is empty",
			referer: "",
			want:    "/",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			p := buildPortal()
			reqURL := url.URL{Scheme: "https", Host: "foo.bar", Path: "/myPage"}
			r := http.Request{URL: &reqURL, Method: "GET"}
			r.Header = make(http.Header)
			if tc.referer != "" {
				r.Header.Set("Referer", tc.referer)
			}
			request := requests.NewRequest()
			rw := buildCustomResponseWriter()

			_ = p.handleHTTPError(context.Background(), rw, &r, request, 404)
			rb := string(rw.body)

			tests.EvalObjectsWithLog(t, "go_back_url", true, strings.Contains(rb, tc.want), []string{})
		})
	}
}
