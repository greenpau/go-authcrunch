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

// Package httpjson requests explicit authorization decisions over HTTP JSON.
package httpjson

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Config specifies an operator-owned endpoint and a per-call timeout. HTTPS is
// required except for literal loopback HTTP addresses. No credentials, query,
// fragment, environment substitution or request-selected endpoints are accepted.
type Config struct {
	Endpoint string `json:"endpoint,omitempty" xml:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Timeout  string `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// Validate checks configuration without I/O and defaults Timeout to 1s.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("HTTP JSON authorizer config is required")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || len(c.Endpoint) > 4096 || !utf8.ValidString(c.Endpoint) || strings.TrimSpace(c.Endpoint) != c.Endpoint || strings.ContainsFunc(c.Endpoint, unicode.IsControl) || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(c.Endpoint, "#") || u.RawQuery != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("HTTP JSON authorizer endpoint is invalid")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("HTTP JSON authorizer endpoint port is invalid")
		}
	}
	if u.Scheme != "https" {
		addr, err := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || err != nil || !addr.IsLoopback() {
			return fmt.Errorf("HTTP JSON authorizer requires HTTPS or literal loopback HTTP")
		}
	}
	if c.Timeout == "" {
		c.Timeout = "1s"
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil || d < time.Millisecond || d > 30*time.Second {
		return fmt.Errorf("HTTP JSON authorizer timeout must be within 1ms-30s")
	}
	return nil
}
