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
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	defaultRefreshAccessLifetime  = 300
	defaultRefreshIdleTimeout     = 1800
	defaultRefreshAbsoluteTimeout = 28800
	defaultRefreshMaxSessions     = 10000
	defaultRefreshMaxRotations    = 1024
	maxRefreshTimeout             = 30 * 24 * 60 * 60
)

// RefreshConfig enables portal refresh for explicitly supported realms. All
// durations are seconds. Nil or disabled configurations preserve access lifetimes.
type RefreshConfig struct {
	Enabled                bool     `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Realms                 []string `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
	PublicOrigin           string   `json:"public_origin,omitempty" xml:"public_origin,omitempty" yaml:"public_origin,omitempty"`
	BasePath               string   `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
	CookieName             string   `json:"cookie_name,omitempty" xml:"cookie_name,omitempty" yaml:"cookie_name,omitempty"`
	AccessLifetimeSeconds  int      `json:"access_lifetime_seconds,omitempty" xml:"access_lifetime_seconds,omitempty" yaml:"access_lifetime_seconds,omitempty"`
	IdleTimeoutSeconds     int      `json:"idle_timeout_seconds,omitempty" xml:"idle_timeout_seconds,omitempty" yaml:"idle_timeout_seconds,omitempty"`
	AbsoluteTimeoutSeconds int      `json:"absolute_timeout_seconds,omitempty" xml:"absolute_timeout_seconds,omitempty" yaml:"absolute_timeout_seconds,omitempty"`
	BodyTransportEnabled   bool     `json:"body_transport_enabled,omitempty" xml:"body_transport_enabled,omitempty" yaml:"body_transport_enabled,omitempty"`
	MaxSessions            int      `json:"max_sessions,omitempty" xml:"max_sessions,omitempty" yaml:"max_sessions,omitempty"`
	MaxRotations           int      `json:"max_rotations,omitempty" xml:"max_rotations,omitempty" yaml:"max_rotations,omitempty"`
}

// Validate normalizes enabled refresh configuration and rejects ambiguous mounts.
func (c *RefreshConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Host != strings.ToLower(u.Host) {
		return fmt.Errorf("refresh public_origin must be an HTTPS origin without a path")
	}
	if !strings.HasPrefix(c.BasePath, "/") || path.Clean(c.BasePath) != c.BasePath || strings.ContainsAny(c.BasePath, "\\%?#;\r\n\t ") {
		return fmt.Errorf("refresh base_path must be a canonical absolute path")
	}
	if c.CookieName == "" {
		d := sha256.Sum256([]byte(c.PublicOrigin + c.BasePath))
		c.CookieName = fmt.Sprintf("__Secure-authcrunch_refresh_%x", d[:8])
	}
	if !strings.HasPrefix(c.CookieName, "__Secure-") && !(strings.HasPrefix(c.CookieName, "__Host-") && c.BasePath == "/") {
		return fmt.Errorf("refresh cookie requires __Secure- prefix, or __Host- at root")
	}
	if err := (&http.Cookie{Name: c.CookieName, Value: "test", Path: c.BasePath, Secure: true}).Valid(); err != nil {
		return fmt.Errorf("invalid refresh cookie name: %w", err)
	}
	if len(c.Realms) == 0 {
		return fmt.Errorf("refresh requires explicit realms")
	}
	seen := make(map[string]bool)
	for _, realm := range c.Realms {
		if strings.TrimSpace(realm) != realm || realm == "" || seen[realm] {
			return fmt.Errorf("invalid or duplicate refresh realm")
		}
		seen[realm] = true
	}
	if c.AccessLifetimeSeconds == 0 {
		c.AccessLifetimeSeconds = defaultRefreshAccessLifetime
	}
	if c.IdleTimeoutSeconds == 0 {
		c.IdleTimeoutSeconds = defaultRefreshIdleTimeout
	}
	if c.AbsoluteTimeoutSeconds == 0 {
		c.AbsoluteTimeoutSeconds = defaultRefreshAbsoluteTimeout
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = defaultRefreshMaxSessions
	}
	if c.MaxRotations == 0 {
		c.MaxRotations = defaultRefreshMaxRotations
	}
	if c.AccessLifetimeSeconds < 1 || c.IdleTimeoutSeconds < 1 || c.AbsoluteTimeoutSeconds < 1 || c.AbsoluteTimeoutSeconds > maxRefreshTimeout || c.AccessLifetimeSeconds > c.AbsoluteTimeoutSeconds || c.IdleTimeoutSeconds > c.AbsoluteTimeoutSeconds {
		return fmt.Errorf("invalid refresh lifetime bounds")
	}
	if c.MaxSessions < 1 || c.MaxRotations < 1 {
		return fmt.Errorf("refresh capacity limits must be positive")
	}
	return nil
}
