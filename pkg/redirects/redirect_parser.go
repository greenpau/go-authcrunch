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
	if !HasRedirectURI(parsedURL) {
		return nil, fmt.Errorf("redirect uri is not url")
	}
	queryParams := parsedURL.Query()
	rawRedirectURI := queryParams.Get("redirect_uri")
	if strings.HasPrefix(rawRedirectURI, "/") {
		return nil, fmt.Errorf("redirect uri has no scheme and host")
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

// GetRedirectURI returns redirect_uri value from query parameters.
func GetRedirectURI(u *url.URL) *url.URL {
	queryParams := u.Query()
	if queryParams == nil {
		return nil
	}
	rawRedirectURI := queryParams.Get("redirect_uri")
	parsedRedirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		return nil
	}
	if parsedRedirectURI.Scheme == "" || parsedRedirectURI.Host == "" || parsedRedirectURI.Path == "" {
		return nil
	}
	return parsedRedirectURI
}

// GetRawRedirectURI returns raw redirect_uri value from query parameters.
func GetRawRedirectURI(u *url.URL) string {
	queryParams := u.Query()
	if queryParams == nil {
		return ""
	}
	return queryParams.Get("redirect_uri")
}

// HasRedirectURI check whether URL has redirect_uri in query parameters.
func HasRedirectURI(u *url.URL) bool {
	queryParams := u.Query()
	if queryParams == nil {
		return false
	}
	rawRedirectURI := queryParams.Get("redirect_uri")
	if rawRedirectURI == "" {
		return false
	}
	return true
}
