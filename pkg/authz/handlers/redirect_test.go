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
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"net/http"
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
