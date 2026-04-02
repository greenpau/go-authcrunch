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
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/cache"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
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
		loginRedirConfig, err := redirects.NewRedirectURIMatchConfig("exact", "foo.bar", "exact", "/redir")
		if err != nil {
			t.Fatalf("failed to build login redirect config: %v", err)
		}

		r := http.Request{URL: &reqURL, Method: "GET"}
		f, _ := cookie.NewFactory(nil)
		p := Portal{
			config: &PortalConfig{
				Name:                           "somePortal",
				TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{loginRedirConfig},
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

		tests.EvalObjectsWithLog(t, "sanitized url", true, strings.Contains(rb, "https://www.google.com/search?hl=en%26q=testing%27%22%28%29%26%25%3Cacx%3E%3CScRiPt%20%3Ealert%289854%29%3C/ScRiPt%3E"), []string{})
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

func buildGrantAccessPortal(trustedConfigs []*redirects.RedirectURIMatchConfig) (*Portal, error) {
	f, err := cookie.NewFactory(nil)
	if err != nil {
		return nil, err
	}
	cfg, err := kms.NewCryptoKeyStoreConfig(nil)
	if err != nil {
		return nil, err
	}
	ks, err := kms.NewCryptoKeyStore(cfg, logutil.NewLogger())
	if err != nil {
		return nil, err
	}
	sessions := cache.NewSessionCache()
	sessions.Run()
	return &Portal{
		config: &PortalConfig{
			Name:                           "testPortal",
			TrustedLoginRedirectURIConfigs: trustedConfigs,
		},
		logger:   zap.L(),
		cookie:   f,
		keystore: ks,
		sessions: sessions,
	}, nil
}

func TestGrantAccessRedirectCookieValidation(t *testing.T) {
	trustedConfig, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.com", "prefix", "/")
	if err != nil {
		t.Fatalf("failed to build redirect config: %v", err)
	}

	var testcases = []struct {
		name           string
		cookieValue    string
		trustedConfigs []*redirects.RedirectURIMatchConfig
		wantLocation   string
	}{
		{
			name:           "trusted redirect cookie honored",
			cookieValue:    "https://app.example.com/dashboard",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			wantLocation:   "https://app.example.com/dashboard",
		},
		{
			name:           "untrusted redirect cookie rejected",
			cookieValue:    "https://evil.example.com/steal",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			wantLocation:   "/portal",
		},
		{
			name:           "no trust configs rejects cookie",
			cookieValue:    "https://app.example.com/dashboard",
			trustedConfigs: nil,
			wantLocation:   "/portal",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := buildGrantAccessPortal(tc.trustedConfigs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			rw := buildCustomResponseWriter()
			r := &http.Request{
				URL:    &url.URL{Scheme: "https", Host: "auth.example.com", Path: "/login"},
				Method: "POST",
				Host:   "auth.example.com",
				Header: http.Header{},
			}
			r.AddCookie(&http.Cookie{Name: p.cookie.RefererCookieName, Value: tc.cookieValue})
			rr := requests.NewRequest()
			rr.Upstream.SessionID = "test-session"
			rr.Upstream.BasePath = "/"
			rr.Upstream.BaseURL = "https://auth.example.com"

			usr, err := user.NewUser(map[string]interface{}{
				"sub":   "testuser",
				"roles": []string{"user"},
				"exp":   float64(9999999999),
				"iat":   float64(1000000000),
				"nbf":   float64(1000000000),
			})
			if err != nil {
				t.Fatalf("failed to create user: %v", err)
			}

			p.grantAccess(context.Background(), rw, r, rr, usr)

			location := rw.Header().Get("Location")
			if strings.HasPrefix(tc.wantLocation, "https://") {
				tests.EvalObjectsWithLog(t, "location", tc.wantLocation, location, []string{})
			} else {
				tests.EvalObjectsWithLog(t, "location", true, strings.HasSuffix(location, tc.wantLocation), []string{})
			}
		})
	}
}
