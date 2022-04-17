// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package addr

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/waf"
	"net/http"
	"strings"
)

const malformedURLStr = "malformed-url"

// GetSourceHost returns the host or host:port of the request.
func GetSourceHost(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-Host")
	if !waf.IsMalformedForwardedHost(h, 2, 255) {
		if h != "" {
			return h
		}
	}
	return r.Host
}

func parseSourceAddress(addr string) string {
	if strings.Contains(addr, ",") {
		addr = strings.TrimSpace(addr)
		addr = strings.SplitN(addr, ",", 2)[0]
	}

	switch {
	case strings.Contains(addr, "["):
		// Handle IPv6 "[host]:port" address.
		return parseAddr6(addr)
	case strings.Contains(addr, "::"):
		// Handle IPv6 address.
		return addr
	}

	if strings.Contains(addr, ":") {
		parts := strings.Split(addr, ":")
		if len(parts) > 2 {
			// Handle IPv6 address.
			return parts[0]
		}
		return parts[0]
	}

	return addr
}

// GetSourceAddress returns the IP address of the request.
func GetSourceAddress(r *http.Request) string {
	if r.Header.Get("X-Real-Ip") != "" {
		if !waf.IsMalformedRealIP(r.Header.Get("X-Real-Ip"), 7, 255) {
			return parseSourceAddress(r.Header.Get("X-Real-Ip"))
		}
	}
	if r.Header.Get("X-Forwarded-For") != "" {
		if !waf.IsMalformedForwardedFor(r.Header.Get("X-Forwarded-For"), 7, 255) {
			return parseSourceAddress(r.Header.Get("X-Forwarded-For"))
		}
	}
	return parseSourceAddress(r.RemoteAddr)
}

// GetSourceConnAddress returns the IP address of the HTTP connection.
func GetSourceConnAddress(r *http.Request) string {
	addr := r.RemoteAddr
	if strings.Contains(addr, ",") {
		addr = strings.TrimSpace(addr)
		addr = strings.SplitN(addr, ",", 2)[0]
	}
	switch {
	case strings.Contains(addr, "["):
		// Handle IPv6 "[host]:port" address.
		return parseAddr6(addr)
	case strings.Contains(addr, "::"):
		// Handle IPv6 address.
		return addr
	}
	if strings.Contains(addr, ":") {
		parts := strings.Split(addr, ":")
		if len(parts) > 2 {
			// Handle IPv6 address.
			return parts[0]
		}
		return parts[0]
	}
	return addr
}

func parseAddr6(s string) string {
	i := strings.IndexByte(s, '[')
	if i < 0 {
		return s
	}
	j := strings.IndexByte(s, ']')
	if j < 0 {
		return s
	}
	if i >= j {
		return s
	}
	return s[(i + 1):j]
}

// GetTargetURL returns the URL the user landed on.
func GetTargetURL(r *http.Request) string {
	s, _ := GetCurrentURLWithSuffix(r, "")
	return s
}

// GetCurrentURLWithSuffix returns current URL based on the provided suffux.
func GetCurrentURLWithSuffix(r *http.Request, suffix string) (string, error) {
	h := r.Header.Get("X-Forwarded-Host")

	if waf.IsMalformedForwardedHost(h, 2, 255) {
		return malformedURLStr, fmt.Errorf("malformed X-Forwarded-Host header")
	}

	if h == "" {
		h = r.Host
	}

	p := r.Header.Get("X-Forwarded-Proto")
	if waf.IsMalformedForwardedProto(p, 2, 10) {
		return malformedURLStr, fmt.Errorf("malformed X-Forwarded-Proto header")
	}

	if p == "" {
		if r.TLS == nil {
			p = "http"
		} else {
			p = "https"
		}
	}

	port := r.Header.Get("X-Forwarded-Port")
	if waf.IsMalformedForwardedPort(port, 2, 5) {
		return malformedURLStr, fmt.Errorf("malformed X-Forwarded-Port header")
	}

	u := p + "://" + h

	if port != "" {
		switch port {
		case "443":
			if p != "https" {
				u += ":" + port
			}
		case "80":
			if p != "http" {
				u += ":" + port
			}
		default:
			u += ":" + port
		}
	}
	if suffix != "" {
		i := strings.Index(r.RequestURI, suffix)
		if i < 0 {
			return u + r.RequestURI, nil
		}
		return u + r.RequestURI[:i] + suffix, nil
	}

	return u + r.RequestURI, nil
}
