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
	"testing"
)

func TestAPIRequestOrigin(t *testing.T) {
	for _, tc := range []struct {
		name           string
		origins, sites []string
		want           bool
	}{
		{name: "native", want: true},
		{name: "same origin", origins: []string{"https://auth.example.test"}, sites: []string{"same-origin"}, want: true},
		{name: "native none", sites: []string{"none"}, want: true},
		{name: "foreign", origins: []string{"https://evil.example.test"}},
		{name: "null", origins: []string{"null"}},
		{name: "empty origin", origins: []string{""}},
		{name: "duplicate origin", origins: []string{"https://auth.example.test", "https://auth.example.test"}},
		{name: "cross site without origin", sites: []string{"cross-site"}},
		{name: "same site without origin", sites: []string{"same-site"}},
		{name: "contradictory metadata", origins: []string{"https://auth.example.test"}, sites: []string{"cross-site"}},
		{name: "duplicate metadata", sites: []string{"same-origin", "same-origin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/api/profile", nil)
			r.RequestURI = r.URL.RequestURI()
			r.Header["Origin"], r.Header["Sec-Fetch-Site"] = tc.origins, tc.sites
			if got := validAPIRequestOrigin(r); got != tc.want {
				t.Fatalf("origin accepted=%t, want %t", got, tc.want)
			}
		})
	}
}
