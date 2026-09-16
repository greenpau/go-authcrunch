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

package bypass

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatchCleansRequestPath(t *testing.T) {
	testcases := []struct {
		name      string
		matchType string
		uri       string
		request   string
		want      bool
	}{
		{
			name:      "prefix allows child below bypass path",
			matchType: "prefix",
			uri:       "/public/",
			request:   "https://example.com/public/assets/app.css",
			want:      true,
		},
		{
			name:      "prefix allows bypass path with trailing slash",
			matchType: "prefix",
			uri:       "/public/",
			request:   "https://example.com/public/",
			want:      true,
		},
		{
			name:      "prefix rejects encoded slash traversal out of bypass path",
			matchType: "prefix",
			uri:       "/public/",
			request:   "https://example.com/public/..%2fadmin",
			want:      false,
		},
		{
			name:      "prefix rejects encoded dot segment traversal out of bypass path",
			matchType: "prefix",
			uri:       "/public/",
			request:   "https://example.com/public/%2e%2e/admin",
			want:      false,
		},
		{
			name:      "prefix rejects literal traversal out of bypass path",
			matchType: "prefix",
			uri:       "/public/",
			request:   "https://example.com/public/../admin",
			want:      false,
		},
		{
			name:      "partial rejects traversal through bypass path",
			matchType: "partial",
			uri:       "/public/",
			request:   "https://example.com/assets/public/../admin",
			want:      false,
		},
		{
			name:      "regex rejects traversal out of bypass path",
			matchType: "regex",
			uri:       `^/public/`,
			request:   "https://example.com/public/../admin",
			want:      false,
		},
		{
			name:      "exact allows canonical bypass path",
			matchType: "exact",
			uri:       "/health/",
			request:   "https://example.com/health/",
			want:      true,
		},
		{
			name:      "exact rejects traversal from bypass path",
			matchType: "exact",
			uri:       "/health/",
			request:   "https://example.com/health/../admin",
			want:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				MatchType: tc.matchType,
				URI:       tc.uri,
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			req := httptest.NewRequest("GET", tc.request, nil)
			if got := Match(req, []*Config{cfg}); got != tc.want {
				t.Fatalf("Match() = %v, want %v; parsed path: %q", got, tc.want, req.URL.Path)
			}
		})
	}
}

func TestMatchEncodedRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name, kind, uri, target string
		want                    bool
	}{
		{"cleaning cannot grant bypass", "prefix", "/public/", "/admin/../public/file", false},
		{"encoded cleaning cannot grant bypass", "prefix", "/public/", "/admin/%2e%2e/public/file", false},
		{"clean before decode", "prefix", "/public/", "/public/a%252fb/../%252e%252e/admin", false},
		{"double dots", "prefix", "/public/", "/public/%252e%252e/admin", false},
		{"double slash", "prefix", "/public/", "/public/..%252fadmin", false},
		{"triple dots", "prefix", "/public/", "/public/%25252e%25252e/admin", false},
		{"private intermediate", "prefix", "/public/", "/public/%252e%252e/admin/%25252e%25252e/public/file", false},
		{"decoding cannot grant bypass", "prefix", "/public/", "/private/%252e%252e/public/file", false},
		{"partial", "partial", "/public/", "/public/%252e%252e/admin", false},
		{"regex", "regex", "^/public/", "/public/%252e%252e/admin", false},
		{"exact", "exact", "/public/%2e%2e/admin", "/public/%252e%252e/admin", false},
		{"suffix", "suffix", "/%2e%2e/admin", "/public/%252e%252e/admin", false},
		{"public child", "prefix", "/public/", "/public/assets/app.css", true},
		{"public directory", "prefix", "/public/", "/public/", true},
		{"exact directory", "exact", "/public/", "/public/", true},
		{"regex directory", "regex", "^/public/$", "/public/", true},
		{"suffix directory", "suffix", "/assets/", "/public/assets/", true},
		{"ordinary escaped filename", "prefix", "/public/", "/public/%2541+file", true},
		{"trailing encoded slash", "prefix", "/public/", "/public/assets%252f", true},
		{"percent in query only", "prefix", "/public/", "/public/file?q=%25zz", true},
		{"literal non-escape", "prefix", "/public/", "/public/%25zz", true},
		{"literal percent", "prefix", "/public/", "/public/100%25", true},
		{"malformed beside traversal", "prefix", "/public/", "/public/%25zz/%252e%252e/admin", false},
		{"malformed cannot match broad rule", "regex", ".*", "/public/%25zz/%252e%252e/admin", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{MatchType: tc.kind, URI: tc.uri}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			path, rawPath, requestURI := r.URL.Path, r.URL.RawPath, r.RequestURI
			if got := Match(r, []*Config{cfg}); got != tc.want {
				t.Fatalf("Match()=%t want=%t Path=%q RawPath=%q RequestURI=%q", got, tc.want, path, rawPath, requestURI)
			}
			if r.URL.Path != path || r.URL.RawPath != rawPath || r.RequestURI != requestURI {
				t.Fatal("matching changed the request handed to the application")
			}
		})
	}
}

func TestMatchRejectsUnresolvedPaths(t *testing.T) {
	cfg := &Config{MatchType: "regex", URI: ".*"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	target := "/public/%2e%2e/admin"
	for range 5 {
		target = strings.ReplaceAll(target, "%", "%25")
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, req := range []*http.Request{nil, {}, r} {
		if Match(req, []*Config{cfg}) {
			t.Fatal("invalid or unresolved request was bypassed")
		}
	}
}
