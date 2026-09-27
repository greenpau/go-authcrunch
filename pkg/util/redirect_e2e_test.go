// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestE2EForwardedPrefixCannotChangeRedirectAuthority(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, GetRelativeURL(r, "/private", "/login"), http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	for _, tc := range []struct {
		name, prefix, wantPath string
	}{
		{name: "malformed authority", prefix: "@attacker.example", wantPath: "/login"},
		{name: "valid mount", prefix: "/tenant", wantPath: "/tenant/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/private", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Forwarded-Prefix", tc.prefix)
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want 302", response.StatusCode)
			}
			destination, err := url.Parse(response.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			origin, _ := url.Parse(server.URL)
			if destination.Scheme != origin.Scheme || destination.Host != origin.Host || destination.User != nil || destination.Path != tc.wantPath {
				t.Fatalf("redirect destination = %q, want origin %q and path %q", destination, origin, tc.wantPath)
			}
		})
	}
}
