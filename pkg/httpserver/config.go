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

// Package httpserver hosts AuthCrunch portals with the Go HTTP server.
package httpserver

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// PortalRoute mounts one named portal at an absolute path. Paths are retained
// when dispatching to the portal, including for nested mounts.
type PortalRoute struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Path string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
}

// Config configures the standalone HTTP listener. Duration strings use Go's
// time.ParseDuration syntax. Empty settings receive bounded defaults. TLS is
// required unless InsecureHTTP is explicitly enabled. Forwarding headers are
// never trusted; HTTPS terminates at this listener.
type Config struct {
	ListenAddress      string        `json:"listen_address,omitempty" xml:"listen_address,omitempty" yaml:"listen_address,omitempty"`
	TLSCertificateFile string        `json:"tls_certificate_file,omitempty" xml:"tls_certificate_file,omitempty" yaml:"tls_certificate_file,omitempty"`
	TLSKeyFile         string        `json:"tls_key_file,omitempty" xml:"tls_key_file,omitempty" yaml:"tls_key_file,omitempty"`
	InsecureHTTP       bool          `json:"insecure_http,omitempty" xml:"insecure_http,omitempty" yaml:"insecure_http,omitempty"`
	ReadHeaderTimeout  string        `json:"read_header_timeout,omitempty" xml:"read_header_timeout,omitempty" yaml:"read_header_timeout,omitempty"`
	ReadTimeout        string        `json:"read_timeout,omitempty" xml:"read_timeout,omitempty" yaml:"read_timeout,omitempty"`
	WriteTimeout       string        `json:"write_timeout,omitempty" xml:"write_timeout,omitempty" yaml:"write_timeout,omitempty"`
	IdleTimeout        string        `json:"idle_timeout,omitempty" xml:"idle_timeout,omitempty" yaml:"idle_timeout,omitempty"`
	ShutdownTimeout    string        `json:"shutdown_timeout,omitempty" xml:"shutdown_timeout,omitempty" yaml:"shutdown_timeout,omitempty"`
	MaxHeaderBytes     int           `json:"max_header_bytes,omitempty" xml:"max_header_bytes,omitempty" yaml:"max_header_bytes,omitempty"`
	Portals            []PortalRoute `json:"portals,omitempty" xml:"portals,omitempty" yaml:"portals,omitempty"`
}

const (
	defaultListenAddress  = "127.0.0.1:8443"
	defaultMaxHeaderBytes = 1 << 20
	maximumTimeout        = 24 * time.Hour
)

// Validate applies transport defaults and checks the complete listener config.
// It does not open files, construct AuthCrunch components, or bind a socket.
func (cfg *Config) Validate() error {
	if cfg == nil {
		return fmt.Errorf("HTTP server configuration is required")
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = defaultListenAddress
	}
	_, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen_address must be a host:port address")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("listen_address requires a numeric port between 0 and 65535")
	}
	if cfg.InsecureHTTP {
		if cfg.TLSCertificateFile != "" || cfg.TLSKeyFile != "" {
			return fmt.Errorf("insecure_http cannot be combined with TLS files")
		}
	} else if cfg.TLSCertificateFile == "" || cfg.TLSKeyFile == "" {
		return fmt.Errorf("TLS certificate and key files are required unless insecure_http is enabled")
	}
	for _, setting := range []struct {
		name     string
		value    *string
		fallback string
	}{
		{"read_header_timeout", &cfg.ReadHeaderTimeout, "10s"},
		{"read_timeout", &cfg.ReadTimeout, "30s"},
		{"write_timeout", &cfg.WriteTimeout, "60s"},
		{"idle_timeout", &cfg.IdleTimeout, "120s"},
		{"shutdown_timeout", &cfg.ShutdownTimeout, "30s"},
	} {
		if *setting.value == "" {
			*setting.value = setting.fallback
		}
		duration, err := time.ParseDuration(*setting.value)
		if err != nil || duration <= 0 || duration > maximumTimeout {
			return fmt.Errorf("%s must be a positive duration at most 24h", setting.name)
		}
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if cfg.MaxHeaderBytes < 1024 || cfg.MaxHeaderBytes > 16*defaultMaxHeaderBytes {
		return fmt.Errorf("max_header_bytes must be between 1024 and 16777216")
	}
	if len(cfg.Portals) == 0 {
		return fmt.Errorf("at least one portal route is required")
	}
	names := make(map[string]bool)
	for i, route := range cfg.Portals {
		if strings.TrimSpace(route.Name) == "" || names[route.Name] {
			return fmt.Errorf("portal route %d has an empty or duplicate name", i+1)
		}
		names[route.Name] = true
		if route.Path == "" || route.Path[0] != '/' || path.Clean(route.Path) != route.Path || strings.ContainsAny(route.Path, "%?#\\ {}") || strings.IndexFunc(route.Path, unicode.IsControl) >= 0 {
			return fmt.Errorf("portal route %d requires a canonical absolute path", i+1)
		}
		// Portal endpoint dispatch discovers its base using these namespaces.
		for segment := range strings.SplitSeq(strings.Trim(route.Path, "/"), "/") {
			// Several legacy base-path helpers match an endpoint prefix rather
			// than a whole segment. For example, /login-service/login would
			// otherwise discover the mount at the first /login occurrence.
			for _, prefix := range []string{"profile", "portal", "recover", "forgot", "register", "whoami", "logout", "favicon", "beacon", "login"} {
				if strings.HasPrefix(segment, prefix) {
					return fmt.Errorf("portal route %d uses a reserved endpoint prefix", i+1)
				}
			}
			switch segment {
			case "api", "qrcode", "sandbox", "apps", "barcode", "saml", "oauth2", "basic", "assets":
				return fmt.Errorf("portal route %d uses a reserved endpoint segment", i+1)
			}
		}
		for _, previous := range cfg.Portals[:i] {
			if route.Path == previous.Path || containsPath(route.Path, previous.Path) || containsPath(previous.Path, route.Path) {
				return fmt.Errorf("portal route %d overlaps another route", i+1)
			}
		}
	}
	return nil
}

func containsPath(mount, target string) bool {
	return mount == "/" || target == mount || strings.HasPrefix(target, mount+"/")
}
