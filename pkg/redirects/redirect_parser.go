// Copyright 2024 Paul Greenberg greenpau@outlook.com
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

package redirects

import (
	"net/url"
	"strings"
)

// ParseRedirectURI parses redirect_uri from URL string.
func ParseRedirectURI(s string) *url.URL {
	parsedURL, err := url.Parse(s)
	if err != nil {
		return nil
	}
	queryParams := parsedURL.Query()
	rawRedirectURI := queryParams.Get("redirect_uri")
	if strings.HasPrefix(rawRedirectURI, "/") {
		return nil
	}
	parsedRedirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		return nil
	}
	return parsedRedirectURI
}
