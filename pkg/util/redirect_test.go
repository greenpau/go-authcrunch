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

package util

import (
	"github.com/greenpau/go-authcrunch/internal/tests"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSanitizeURLPath(t *testing.T) {
	var testcases = []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean path passes through unchanged",
			input: "/auth/login",
			want:  "/auth/login",
		},
		{
			name:  "root path passes through unchanged",
			input: "/",
			want:  "/",
		},
		{
			name:  "empty string passes through unchanged",
			input: "",
			want:  "",
		},
		{
			name:  "script tag in path segment is encoded",
			input: `/auth"><script>alert(1)</script>`,
			want:  `/auth%22%3E%3Cscript%3Ealert%281%29%3C/script%3E`,
		},
		{
			name:  "double quotes in path segment are encoded",
			input: `/auth" onclick="alert(1)`,
			want:  `/auth%22%20onclick=%22alert%281%29`,
		},
		{
			name:  "single quotes in path segment are encoded",
			input: "/auth'><img src=x onerror=alert(1)>",
			want:  "/auth%27%3E%3Cimg%20src=x%20onerror=alert%281%29%3E",
		},
		{
			name:  "path with hyphens and dots passes through",
			input: "/auth/my-app/v2.0",
			want:  "/auth/my-app/v2.0",
		},
		{
			name:  "path with tilde and underscore passes through",
			input: "/auth/my_app/~user",
			want:  "/auth/my_app/~user",
		},
		{
			// r.URL.Path is pre-decoded by net/http, so percent literals
			// only appear if the raw request contained a literal %25.
			// Double-encoding is expected and correct here.
			name:  "percent in decoded path is re-encoded",
			input: "/auth/%22foo",
			want:  "/auth/%2522foo",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeURLPath(tc.input)
			tests.EvalObjectsWithLog(t, "sanitized path", tc.want, got, []string{})
		})
	}
}

func TestGetBaseURLSanitizesPath(t *testing.T) {
	var testcases = []struct {
		name     string
		path     string
		match    string
		wantPath string
	}{
		{
			name:     "normal path returns clean base",
			path:     "/auth/login",
			match:    "/login",
			wantPath: "/auth",
		},
		{
			name:     "XSS payload in path is sanitized",
			path:     `/auth"><script>alert(1)</script>/login`,
			match:    "/login",
			wantPath: `/auth%22%3E%3Cscript%3Ealert%281%29%3C/script%3E`,
		},
		{
			name:     "event handler injection in path is sanitized",
			path:     `/auth" onmouseover="alert(1)/login`,
			match:    "/login",
			wantPath: `/auth%22%20onmouseover=%22alert%281%29`,
		},
		{
			name:     "no match returns full sanitized path",
			path:     `/<img src=x>/nomatch`,
			match:    "/willnotmatch",
			wantPath: `/%3Cimg%20src=x%3E/nomatch`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				URL:  &url.URL{Path: tc.path},
				Host: "localhost",
			}
			_, basePath := GetBaseURL(r, tc.match)
			tests.EvalObjectsWithLog(t, "base path", tc.wantPath, basePath, []string{})
		})
	}
}

func TestGetCurrentURLSanitizesPath(t *testing.T) {
	var testcases = []struct {
		name     string
		path     string
		wantSafe bool
	}{
		{
			name:     "clean path passes through",
			path:     "/auth/login",
			wantSafe: true,
		},
		{
			name:     "XSS payload in path is sanitized",
			path:     `/auth"><script>alert(1)</script>/callback`,
			wantSafe: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				URL:  &url.URL{Path: tc.path},
				Host: "localhost",
			}
			got := GetCurrentURL(r)
			if tc.wantSafe && (strings.Contains(got, "<") || strings.Contains(got, ">") || strings.Contains(got, `"`)) {
				t.Errorf("GetCurrentURL() returned unsanitized HTML chars: %s", got)
			}
		})
	}
}

func TestStripQueryParam(t *testing.T) {

	var testcases = []struct {
		name  string
		url   string
		param string
		want  string
	}{
		{
			name:  "removes a specific query param from a URL",
			url:   "https://foo.bar/myPage?param1=value&param2=otherValue",
			param: "param2",
			want:  "https://foo.bar/myPage?param1=value",
		},
		{
			name:  "returns original URL if URL cannot be parsed",
			url:   "glibberish",
			param: "myParam",
			want:  "glibberish",
		},
		{
			name:  "returns original URL if param does not exist in URL",
			url:   "https://foo.bar/myPage?param1=value",
			param: "myParam",
			want:  "https://foo.bar/myPage?param1=value",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			alteredURL := StripQueryParam(tc.url, tc.param)
			tests.EvalObjectsWithLog(t, "stripped url", tc.want, alteredURL, []string{})
		})
	}
}
