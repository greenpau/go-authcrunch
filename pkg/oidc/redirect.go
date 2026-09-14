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

package oidc

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// parseOIDCRedirectURI validates syntax without normalizing a registered value.
func parseOIDCRedirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(raw, "#\\\r\n\t ") || len(raw) > 2048 {
		return nil, fmt.Errorf("invalid oidc redirect_uri")
	}
	// URL.Parse permits numeric ports outside the TCP range and an explicitly
	// empty port. Neither denotes a usable native callback listener.
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("invalid oidc redirect_uri port")
	}
	if port := u.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("invalid oidc redirect_uri port")
		}
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return nil, fmt.Errorf("invalid oidc redirect_uri query")
	}
	return u, nil
}

// loopbackRedirectHost identifies the supported native callback subset: HTTP
// with an exact IPv4 or IPv6 loopback literal. Hostnames, mapped IPs, zones, and
// alternative textual forms do not receive the RFC 8252 port exception.
func loopbackRedirectHost(u *url.URL) string {
	if u.Scheme != "http" {
		return ""
	}
	for _, literal := range []string{"127.0.0.1", "[::1]"} {
		if u.Host == literal || (u.Port() != "" && u.Host == literal+":"+u.Port()) {
			return literal
		}
	}
	return ""
}

// loopbackRedirectWithoutPort removes only the port bytes. All other bytes,
// including raw path/query encoding, scheme case, and a trailing '?', remain
// significant. Re-serializing url.URL here would weaken exact URI matching.
func loopbackRedirectWithoutPort(raw string) (string, bool) {
	u, err := parseOIDCRedirectURI(raw)
	if err != nil {
		return "", false
	}
	host := loopbackRedirectHost(u)
	if host == "" {
		return "", false
	}
	start := strings.Index(raw, "://") + 3
	if start < 3 || !strings.HasPrefix(raw[start:], u.Host) {
		return "", false
	}
	return raw[:start] + host + raw[start+len(u.Host):], true
}

// allowsRedirectURI is called only for validated, immutable registrations.
// A public HTTP loopback registration declares the supported native client
// subset; all other registrations require a byte-for-byte exact match.
func (c *ClientConfig) allowsRedirectURI(raw string) bool {
	if slices.Contains(c.RedirectURIs, raw) {
		return true
	}
	if c.TokenEndpointAuthMethod != "none" || !c.RequirePKCE {
		return false
	}
	candidate, ok := loopbackRedirectWithoutPort(raw)
	if !ok {
		return false
	}
	for _, registered := range c.RedirectURIs {
		if expected, ok := loopbackRedirectWithoutPort(registered); ok && candidate == expected {
			return true
		}
	}
	return false
}
