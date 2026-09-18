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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// getWebAuthnExpectedOrigin derives the WebAuthn origin from the same trusted
// request metadata used to embed the portal. The embedding server is responsible
// for removing untrusted forwarded headers before invoking the portal.
func getWebAuthnExpectedOrigin(r *http.Request) (string, error) {
	currentURL, err := addrutil.GetCurrentURLWithSuffix(r, "/")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(currentURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("failed to derive WebAuthn origin")
	}
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	if (scheme != "https" && scheme != "http") || hostname == "" {
		return "", fmt.Errorf("failed to derive WebAuthn origin")
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	return (&url.URL{Scheme: scheme, Host: host}).String(), nil
}
