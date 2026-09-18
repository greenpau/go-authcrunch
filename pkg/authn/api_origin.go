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

import "net/http"

// validAPIRequestOrigin protects cookie-authorized API actions from browser
// submissions on another origin, including another origin on the same site.
// Header-less native clients remain supported. The embedding server owns
// normalization of forwarded request metadata used to derive the public origin.
func validAPIRequestOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return false
	}
	if len(origins) == 1 {
		expected, err := getWebAuthnExpectedOrigin(r)
		if err != nil || origins[0] != expected {
			return false
		}
	}
	sites := r.Header.Values("Sec-Fetch-Site")
	return len(sites) == 0 || (len(sites) == 1 && (sites[0] == "same-origin" || sites[0] == "none"))
}
