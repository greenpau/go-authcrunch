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

package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/requests"
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

func TestRedirect(t *testing.T) {
	var testcases = []struct {
		name              string
		expectedAuthURL   string
		expectedSeparator string
		testCase          requests.AuthorizationRequest
	}{
		{
			name:              "returns a AuthUrl as it is",
			expectedAuthURL:   "something.com",
			expectedSeparator: "?",
			testCase: requests.AuthorizationRequest{
				Redirect: requests.RedirectResponse{
					AuthURL:        "something.com",
					QueryParameter: "redirect_url",
				},
			},
		},
		{
			name:              "returns a AuthUrl with loginHint only",
			expectedAuthURL:   "something.com?login_hint=fakemail%40byom.de",
			expectedSeparator: "&",
			testCase: requests.AuthorizationRequest{
				Redirect: requests.RedirectResponse{
					LoginHint:      "fakemail@byom.de",
					AuthURL:        "something.com",
					QueryParameter: "redirect_url",
				},
			},
		},
		{
			name:              "returns a AuthUrl with additional scopes only",
			expectedAuthURL:   "something.com?additional_scopes=scopeA+scopeB",
			expectedSeparator: "&",
			testCase: requests.AuthorizationRequest{
				Redirect: requests.RedirectResponse{
					AdditionalScopes: "scopeA scopeB",
					AuthURL:          "something.com",
					QueryParameter:   "redirect_url",
				},
			},
		},
		{
			name:              "returns a AuthUrl with additional scopes and login hint",
			expectedAuthURL:   "something.com?login_hint=fakemail%40byom.de&additional_scopes=scopeA+scopeB",
			expectedSeparator: "&",
			testCase: requests.AuthorizationRequest{
				Redirect: requests.RedirectResponse{
					LoginHint:        "fakemail@byom.de",
					AdditionalScopes: "scopeA scopeB",
					AuthURL:          "something.com",
					QueryParameter:   "redirect_url",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "https://foo.bar", nil)
			configureRedirect(buildCustomResponseWriter(), r, &tc.testCase)
			tests.EvalObjects(t, "check the expected AuthUrl", tc.expectedAuthURL, tc.testCase.Redirect.AuthURL)
			tests.EvalObjects(t, "check the expected Separator", tc.expectedSeparator, tc.testCase.Redirect.Separator)
		})
	}
}

func TestLocationHeaderRedirectKeepsRequestURLInQuery(t *testing.T) {
	// The request-derived URL is return data inside a query parameter. The
	// configured AuthURL remains the redirect's scheme and authority.
	testcases := []struct {
		name           string
		requestURI     string
		headers        http.Header
		authURL        string
		wantHost       string
		wantPath       string
		wantRequestURL string
	}{
		{
			name:           "origin form double slash",
			requestURI:     "//evil.example/private",
			authURL:        "/login",
			wantPath:       "/login",
			wantRequestURL: "https://service.example//evil.example/private",
		},
		{
			name:           "encoded authority characters",
			requestURI:     "/%5C%5Cevil.example/%2F%2Fprivate",
			authURL:        "/login",
			wantPath:       "/login",
			wantRequestURL: "https://service.example/%5C%5Cevil.example/%2F%2Fprivate",
		},
		{
			name:           "absolute form remains a parameter",
			requestURI:     "https://evil.example/private",
			authURL:        "/login",
			wantPath:       "/login",
			wantRequestURL: "https://evil.example/private",
		},
		{
			name:       "forwarded authority does not replace configured destination",
			requestURI: "/private",
			headers: http.Header{
				"X-Forwarded-Host":  []string{"evil.example"},
				"X-Forwarded-Proto": []string{"https"},
			},
			authURL:        "https://auth.example/login?tenant=one",
			wantHost:       "auth.example",
			wantPath:       "/login",
			wantRequestURL: "https://evil.example/private",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
			requestTarget, err := url.ParseRequestURI(tc.requestURI)
			if err != nil {
				t.Fatalf("parse request target: %v", err)
			}
			r.RequestURI = tc.requestURI
			r.URL = requestTarget
			for name, values := range tc.headers {
				for _, value := range values {
					r.Header.Add(name, value)
				}
			}
			rr := requests.NewAuthorizationRequest()
			rr.Redirect.AuthURL = tc.authURL
			rr.Redirect.QueryParameter = "return_url"
			w := httptest.NewRecorder()

			HandleLocationHeaderRedirect(w, r, rr)
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if location.Host != tc.wantHost || location.Path != tc.wantPath {
				t.Fatalf("redirect destination = %q%q, want %q%q", location.Host, location.Path, tc.wantHost, tc.wantPath)
			}
			if got := location.Query().Get("return_url"); got != tc.wantRequestURL {
				t.Fatalf("return_url = %q, want %q; Location=%q", got, tc.wantRequestURL, location.String())
			}
		})
	}
}

func TestLocationHeaderRedirectWithoutQueryUsesConfiguredDestination(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://service.example//evil.example/private", nil)
	rr := requests.NewAuthorizationRequest()
	rr.Redirect.AuthURL = "https://auth.example/login"
	rr.Redirect.QueryParameter = "return_url"
	rr.Redirect.QueryDisabled = true
	w := httptest.NewRecorder()

	HandleLocationHeaderRedirect(w, r, rr)
	if got := w.Header().Get("Location"); got != rr.Redirect.AuthURL {
		t.Fatalf("Location = %q, want configured destination %q", got, rr.Redirect.AuthURL)
	}
}

func TestLocationHeaderRedirectRejectsMissingParsedURL(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
	r.URL = nil
	rr := requests.NewAuthorizationRequest()
	rr.Redirect.AuthURL = "https://auth.example/login"
	rr.Redirect.QueryParameter = "return_url"
	w := httptest.NewRecorder()

	HandleLocationHeaderRedirect(w, r, rr)
	if rr.Redirect.Enabled {
		t.Fatal("redirect enabled without a parsed request URL")
	}
	if location := w.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want empty", location)
	}
}

func TestJavascriptRedirectKeepsRequestURLInEncodedParameter(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
	r.RequestURI = "//evil.example/private"
	requestTarget, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		t.Fatalf("parse request target: %v", err)
	}
	r.URL = requestTarget
	rr := requests.NewAuthorizationRequest()
	rr.Redirect.AuthURL = "https://auth.example/login"
	rr.Redirect.QueryParameter = "return_url"
	w := httptest.NewRecorder()

	HandleJavascriptRedirect(w, r, rr)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if rr.Redirect.AuthURL != "https://auth.example/login" {
		t.Fatalf("AuthURL = %q, want configured destination", rr.Redirect.AuthURL)
	}
	if rr.Redirect.URL != "https://service.example//evil.example/private" {
		t.Fatalf("return URL = %q, want request URL", rr.Redirect.URL)
	}
	body := w.Body.String()
	for _, want := range []string{
		`var auth_url_path = "https:\/\/auth.example\/login";`,
		`var redir_url = "https:\/\/service.example\/\/evil.example\/private";`,
		`encodeURIComponent(redir_url)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Javascript redirect response does not contain %q:\n%s", want, body)
		}
	}
}
