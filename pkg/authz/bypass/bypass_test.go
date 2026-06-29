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
	"net/http/httptest"
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
