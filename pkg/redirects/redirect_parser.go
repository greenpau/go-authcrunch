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
	"fmt"
	"net/url"
	"strings"
)

// ParseRedirectURI parses redirect_uri from URL string.
func ParseRedirectURI(s string) (*url.URL, error) {
	parsedURL, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base uri")
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" || parsedURL.Path == "" {
		return nil, fmt.Errorf("non compliant base uri")
	}
	queryParams := parsedURL.Query()
	rawRedirectURI := queryParams.Get("redirect_uri")
	if strings.HasPrefix(rawRedirectURI, "/") {
		return nil, fmt.Errorf("redirect uri is not url")
	}
	parsedRedirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redirect uri")
	}
	if parsedRedirectURI.Scheme == "" || parsedRedirectURI.Host == "" || parsedRedirectURI.Path == "" {
		return nil, fmt.Errorf("non compliant redirect uri")
	}
	return parsedRedirectURI, nil
}
